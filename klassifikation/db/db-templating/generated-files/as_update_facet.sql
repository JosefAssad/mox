-- Copyright (C) 2015 Magenta ApS, http://magenta.dk.
-- Contact: info@magenta.dk.
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*
NOTICE: This file is auto-generated using the script: apply-template.py facet as_update.jinja.sql
*/



--Please notice that is it the responsibility of the invoker of this function to compare the resulting facet_registration (including the entire hierarchy)
--to the previous one, and abort the transaction if the two registrations are identical. (This is to comply with the stipulated behavior in 'Specifikation_af_generelle_egenskaber - til OIOkomiteen.pdf')

--Also notice, that the given array of FacetAttr...Type must be consistent regarding virkning (although the allowance of null-values might make it possible to construct 'logically consistent'-arrays of objects with overlapping virknings)

CREATE OR REPLACE FUNCTION as_update_facet(
  facet_uuid uuid,
  brugerref uuid,
  note text,
  livscykluskode Livscykluskode,           
  attrEgenskaber FacetEgenskaberAttrType[],
  tilsPubliceret FacetPubliceretTilsType[],
  relationer FacetRelationType[],
  lostUpdatePreventionTZ TIMESTAMPTZ = null
	)
  RETURNS bigint AS 
$$
DECLARE
  read_new_facet FacetType;
  read_prev_facet FacetType;
  read_new_facet_reg FacetRegistreringType;
  read_prev_facet_reg FacetRegistreringType;
  new_facet_registrering facet_registrering;
  prev_facet_registrering facet_registrering;
  facet_relation_navn FacetRelationKode;
  attrEgenskaberObj FacetEgenskaberAttrType;
BEGIN

--create a new registrering

IF NOT EXISTS (select a.id from facet a join facet_registrering b on b.facet_id=a.id  where a.id=facet_uuid) THEN
   RAISE EXCEPTION 'Unable to update facet with uuid [%], being unable to any previous registrations.',facet_uuid;
END IF;

new_facet_registrering := _as_create_facet_registrering(facet_uuid,livscykluskode, brugerref, note);
prev_facet_registrering := _as_get_prev_facet_registrering(new_facet_registrering);

IF lostUpdatePreventionTZ IS NOT NULL THEN
  IF NOT (LOWER((prev_facet_registrering.registrering).timeperiod)=lostUpdatePreventionTZ) THEN
    RAISE EXCEPTION 'Unable to update facet with uuid [%], as the facet seems to have been updated since latest read by client (the given lostUpdatePreventionTZ [%] does not match the timesamp of latest registration [%]).',facet_uuid,lostUpdatePreventionTZ,LOWER((prev_facet_registrering.registrering).timeperiod);
  END IF;   
END IF;

--handle relationer (relations)


--1) Insert relations given as part of this update
--2) Insert relations of previous registration, taking overlapping virknings into consideration (using function subtract_tstzrange)

--Ad 1)



    INSERT INTO facet_relation (
      facet_registrering_id,
        virkning,
          rel_maal,
            rel_type
    )
    SELECT
      new_facet_registrering.id,
        a.virkning,
          a.relMaal,
            a.relType
    FROM unnest(relationer) as a
  ;

 
--Ad 2)

/**********************/
-- 0..1 relations 

FOREACH facet_relation_navn in array  ARRAY['ansvarlig'::FacetRelationKode,'ejer'::FacetRelationKode,'facettilhoerer'::FacetRelationKode]
LOOP

  INSERT INTO facet_relation (
      facet_registrering_id,
        virkning,
          rel_maal,
            rel_type
    )
  SELECT 
      new_facet_registrering.id, 
        ROW(
          c.tz_range_leftover,
            (a.virkning).AktoerRef,
            (a.virkning).AktoerTypeKode,
            (a.virkning).NoteTekst
        ) :: virkning,
          a.rel_maal,
            a.rel_type
  FROM
  (
    --build an array of the timeperiod of the virkning of the relations of the new registrering to pass to _subtract_tstzrange_arr on the relations of the previous registrering 
    SELECT coalesce(array_agg((b.virkning).TimePeriod),array[]::TSTZRANGE[]) tzranges_of_new_reg
    FROM facet_relation b
    WHERE 
          b.facet_registrering_id=new_facet_registrering.id
          and
          b.rel_type=facet_relation_navn
  ) d
  JOIN facet_relation a ON true
  JOIN unnest(_subtract_tstzrange_arr((a.virkning).TimePeriod,tzranges_of_new_reg)) as c(tz_range_leftover) on true
  WHERE a.facet_registrering_id=prev_facet_registrering.id 
        and a.rel_type=facet_relation_navn 
  ;
END LOOP;

/**********************/
-- 0..n relations

--The question regarding how the api-consumer is to specify the deletion of 0..n relation already registered is not answered.
--The following options presents itself:
--a) In this special case, the api-consumer has to specify the full set of the 0..n relation, when updating 
-- ref: ("Hvis indholdet i en liste af elementer rettes, skal hele den nye liste af elementer med i ObjektRet - p27 "Generelle egenskaber for serviceinterfaces på sags- og dokumentområdet")

--Assuming option 'a' above is selected, we only have to check if there are any of the relations with the given name present in the new registration, otherwise copy the ones from the previous registration


FOREACH facet_relation_navn in array ARRAY['redaktoerer'::FacetRelationKode]
LOOP

  IF NOT EXISTS  (SELECT 1 FROM facet_relation WHERE facet_registrering_id=new_facet_registrering.id and rel_type=facet_relation_navn) THEN

    INSERT INTO facet_relation (
          facet_registrering_id,
            virkning,
              rel_maal,
                rel_type
        )
    SELECT 
          new_facet_registrering.id,
            virkning,
              rel_maal,
                rel_type
    FROM facet_relation
    WHERE facet_registrering_id=prev_facet_registrering.id 
    and rel_type=facet_relation_navn 
    ;

  END IF;
            
END LOOP;
/**********************/
-- handle tilstande (states)

--1) Insert tilstande/states given as part of this update
--2) Insert tilstande/states of previous registration, taking overlapping virknings into consideration (using function subtract_tstzrange)

/********************************************/
--facet_tils_publiceret
/********************************************/

--Ad 1)

INSERT INTO facet_tils_publiceret (
        virkning,
          publiceret,
            facet_registrering_id
) 
SELECT
        a.virkning,
          a.publiceret,
            new_facet_registrering.id
FROM
unnest(tilsPubliceret) as a
;
 

--Ad 2

INSERT INTO facet_tils_publiceret (
        virkning,
          publiceret,
            facet_registrering_id
)
SELECT 
        ROW(
          c.tz_range_leftover,
            (a.virkning).AktoerRef,
            (a.virkning).AktoerTypeKode,
            (a.virkning).NoteTekst
        ) :: virkning,
          a.publiceret,
            new_facet_registrering.id
FROM
(
 --build an array of the timeperiod of the virkning of the facet_tils_publiceret of the new registrering to pass to _subtract_tstzrange_arr on the facet_tils_publiceret of the previous registrering 
    SELECT coalesce(array_agg((b.virkning).TimePeriod),array[]::TSTZRANGE[]) tzranges_of_new_reg
    FROM facet_tils_publiceret b
    WHERE 
          b.facet_registrering_id=new_facet_registrering.id
) d
  JOIN facet_tils_publiceret a ON true  
  JOIN unnest(_subtract_tstzrange_arr((a.virkning).TimePeriod,tzranges_of_new_reg)) as c(tz_range_leftover) on true
  WHERE a.facet_registrering_id=prev_facet_registrering.id     
;


/**********************/
--Handle attributter (attributes) 

/********************************************/
--facet_attr_egenskaber
/********************************************/

--Generate and insert any merged objects, if any fields are null in attrFacetObj
IF attrEgenskaber IS NOT null THEN
  FOREACH attrEgenskaberObj in array attrEgenskaber
  LOOP

  --To avoid needless fragmentation we'll check for presence of null values in the fields - and if none are present, we'll skip the merging operations
  IF (attrEgenskaberObj).brugervendtnoegle is null OR 
   (attrEgenskaberObj).beskrivelse is null OR 
   (attrEgenskaberObj).opbygning is null OR 
   (attrEgenskaberObj).ophavsret is null OR 
   (attrEgenskaberObj).plan is null OR 
   (attrEgenskaberObj).supplement is null OR 
   (attrEgenskaberObj).retskilde is null 
  THEN

  INSERT INTO
  facet_attr_egenskaber
  (
    brugervendtnoegle,beskrivelse,opbygning,ophavsret,plan,supplement,retskilde
    ,virkning
    ,facet_registrering_id
  )
  SELECT 
    coalesce(attrEgenskaberObj.brugervendtnoegle,a.brugervendtnoegle), 
    coalesce(attrEgenskaberObj.beskrivelse,a.beskrivelse), 
    coalesce(attrEgenskaberObj.opbygning,a.opbygning), 
    coalesce(attrEgenskaberObj.ophavsret,a.ophavsret), 
    coalesce(attrEgenskaberObj.plan,a.plan), 
    coalesce(attrEgenskaberObj.supplement,a.supplement), 
    coalesce(attrEgenskaberObj.retskilde,a.retskilde),
	ROW (
	  (a.virkning).TimePeriod * (attrEgenskaberObj.virkning).TimePeriod,
	  (attrEgenskaberObj.virkning).AktoerRef,
	  (attrEgenskaberObj.virkning).AktoerTypeKode,
	  (attrEgenskaberObj.virkning).NoteTekst
	)::Virkning,
    new_facet_registrering.id
  FROM facet_attr_egenskaber a
  WHERE
    a.facet_registrering_id=prev_facet_registrering.id 
    and (a.virkning).TimePeriod && (attrEgenskaberObj.virkning).TimePeriod
  ;

  --For any periods within the virkning of the attrEgenskaberObj, that is NOT covered by any "merged" rows inserted above, generate and insert rows

  INSERT INTO
  facet_attr_egenskaber
  (
    brugervendtnoegle,beskrivelse,opbygning,ophavsret,plan,supplement,retskilde
    ,virkning
    ,facet_registrering_id
  )
  SELECT 
    attrEgenskaberObj.brugervendtnoegle, 
    attrEgenskaberObj.beskrivelse, 
    attrEgenskaberObj.opbygning, 
    attrEgenskaberObj.ophavsret, 
    attrEgenskaberObj.plan, 
    attrEgenskaberObj.supplement, 
    attrEgenskaberObj.retskilde,
	  ROW (
	       b.tz_range_leftover,
	      (attrEgenskaberObj.virkning).AktoerRef,
	      (attrEgenskaberObj.virkning).AktoerTypeKode,
	      (attrEgenskaberObj.virkning).NoteTekst
	  )::Virkning,
    new_facet_registrering.id
  FROM
  (
  --build an array of the timeperiod of the virkning of the facet_attr_egenskaber of the new registrering to pass to _subtract_tstzrange_arr 
      SELECT coalesce(array_agg((b.virkning).TimePeriod),array[]::TSTZRANGE[]) tzranges_of_new_reg
      FROM facet_attr_egenskaber b
      WHERE 
       b.facet_registrering_id=new_facet_registrering.id
  ) as a
  JOIN unnest(_subtract_tstzrange_arr((attrEgenskaberObj.virkning).TimePeriod,a.tzranges_of_new_reg)) as b(tz_range_leftover) on true
  ;

  ELSE
    --insert attrEgenskaberObj raw (if there were no null-valued fields) 

    INSERT INTO
    facet_attr_egenskaber
    (
    brugervendtnoegle,beskrivelse,opbygning,ophavsret,plan,supplement,retskilde
    ,virkning
    ,facet_registrering_id
    )
    VALUES ( 
    attrEgenskaberObj.brugervendtnoegle, 
    attrEgenskaberObj.beskrivelse, 
    attrEgenskaberObj.opbygning, 
    attrEgenskaberObj.ophavsret, 
    attrEgenskaberObj.plan, 
    attrEgenskaberObj.supplement, 
    attrEgenskaberObj.retskilde,
    attrEgenskaberObj.virkning,
    new_facet_registrering.id
    );

  END IF;

  END LOOP;
END IF;

--Handle egenskaber of previous registration, taking overlapping virknings into consideration (using function subtract_tstzrange)

INSERT INTO facet_attr_egenskaber (
    brugervendtnoegle,beskrivelse,opbygning,ophavsret,plan,supplement,retskilde
    ,virkning
    ,facet_registrering_id
)
SELECT
      a.brugervendtnoegle,
      a.beskrivelse,
      a.opbygning,
      a.ophavsret,
      a.plan,
      a.supplement,
      a.retskilde,
	  ROW(
	    c.tz_range_leftover,
	      (a.virkning).AktoerRef,
	      (a.virkning).AktoerTypeKode,
	      (a.virkning).NoteTekst
	  ) :: virkning,
	 new_facet_registrering.id
FROM
(
 --build an array of the timeperiod of the virkning of the facet_attr_egenskaber of the new registrering to pass to _subtract_tstzrange_arr on the facet_attr_egenskaber of the previous registrering 
    SELECT coalesce(array_agg((b.virkning).TimePeriod),array[]::TSTZRANGE[]) tzranges_of_new_reg
    FROM facet_attr_egenskaber b
    WHERE 
          b.facet_registrering_id=new_facet_registrering.id
) d
  JOIN facet_attr_egenskaber a ON true  
  JOIN unnest(_subtract_tstzrange_arr((a.virkning).TimePeriod,tzranges_of_new_reg)) as c(tz_range_leftover) on true
  WHERE a.facet_registrering_id=prev_facet_registrering.id     
;


/******************************************************************/
--If the new registrering is identical to the previous one, we need to throw an exception to abort the transaction. 

read_new_facet:=as_read_facet(facet_uuid, (new_facet_registrering.registrering).timeperiod,null);
read_prev_facet:=as_read_facet(facet_uuid, (prev_facet_registrering.registrering).timeperiod ,null);
 
 /*
read_new_facet_reg facetRegistreringType;
read_prev_facet_reg facetRegistreringType;
*/

--the ordering in as_list (called by as_read) ensures that the latest registration is returned at index pos 1

/*
--TODO
IF NOT (read_new_facet.registrering[1].registrering=new_facet_registrering AND read_prev_facet.registrering[1].registrering=prev_facet_registrering) THEN
  RAISE EXCEPTION 'Error updating facet with id [%]: The ordering of as_list_facet should ensure that the latest registrering can be found at index 1. Expected new reg: [%]. Actual new reg at index 1: [%]. Expected prev reg: [%]. Actual prev reg at index 1: [%].  ',facet_uuid,to_json(new_facet_registrering),to_json(read_new_facet.registrering[1].registrering),to_json(prev_facet_registrering),to_json(prev_new_facet.registrering[1].registrering);
END IF;
 */
 --we'll ignore the registreringBase part in the comparrison - except for the livcykluskode

read_new_facet_reg:=ROW(
ROW(null,(read_new_facet.registrering[1].registrering).livscykluskode,null,null)::registreringBase,
(read_new_facet.registrering[1]).tilsPubliceret ,
(read_new_facet.registrering[1]).attrEgenskaber ,
relationer 
)::facetRegistreringType
;

read_prev_facet_reg:=ROW(
ROW(null,(read_prev_facet.registrering[1].registrering).livscykluskode,null,null)::registreringBase,
(read_prev_facet.registrering[1]).tilsPubliceret ,
(read_prev_facet.registrering[1]).attrEgenskaber ,
relationer 
)::facetRegistreringType
;


IF read_prev_facet_reg=read_new_facet_reg THEN
  RAISE EXCEPTION 'Aborted updating facet with id [%] as the given data, does not give raise to a new registration. Aborted reg:[%], previous reg:[%]',facet_uuid,to_json(read_new_facet_reg),to_json(read_prev_facet_reg) USING ERRCODE = 22000;
END IF;

/******************************************************************/


return new_facet_registrering.id;



END;
$$ LANGUAGE plpgsql VOLATILE;





