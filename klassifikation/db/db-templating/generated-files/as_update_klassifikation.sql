-- Copyright (C) 2015 Magenta ApS, http://magenta.dk.
-- Contact: info@magenta.dk.
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*
NOTICE: This file is auto-generated using the script: apply-template.py klassifikation as_update.jinja.sql
*/



--Please notice that is it the responsibility of the invoker of this function to compare the resulting klassifikation_registration (including the entire hierarchy)
--to the previous one, and abort the transaction if the two registrations are identical. (This is to comply with the stipulated behavior in 'Specifikation_af_generelle_egenskaber - til OIOkomiteen.pdf')

--Also notice, that the given array of KlassifikationAttr...Type must be consistent regarding virkning (although the allowance of null-values might make it possible to construct 'logically consistent'-arrays of objects with overlapping virknings)

CREATE OR REPLACE FUNCTION as_update_klassifikation(
  klassifikation_uuid uuid,
  brugerref uuid,
  note text,
  livscykluskode Livscykluskode,           
  attrEgenskaber KlassifikationEgenskaberAttrType[],
  tilsPubliceret KlassifikationPubliceretTilsType[],
  relationer KlassifikationRelationType[],
  lostUpdatePreventionTZ TIMESTAMPTZ = null
	)
  RETURNS bigint AS 
$$
DECLARE
  read_new_klassifikation KlassifikationType;
  read_prev_klassifikation KlassifikationType;
  read_new_klassifikation_reg KlassifikationRegistreringType;
  read_prev_klassifikation_reg KlassifikationRegistreringType;
  new_klassifikation_registrering klassifikation_registrering;
  prev_klassifikation_registrering klassifikation_registrering;
  klassifikation_relation_navn KlassifikationRelationKode;
  attrEgenskaberObj KlassifikationEgenskaberAttrType;
BEGIN

--create a new registrering

IF NOT EXISTS (select a.id from klassifikation a join klassifikation_registrering b on b.klassifikation_id=a.id  where a.id=klassifikation_uuid) THEN
   RAISE EXCEPTION 'Unable to update klassifikation with uuid [%], being unable to any previous registrations.',klassifikation_uuid;
END IF;

new_klassifikation_registrering := _as_create_klassifikation_registrering(klassifikation_uuid,livscykluskode, brugerref, note);
prev_klassifikation_registrering := _as_get_prev_klassifikation_registrering(new_klassifikation_registrering);

IF lostUpdatePreventionTZ IS NOT NULL THEN
  IF NOT (LOWER((prev_klassifikation_registrering.registrering).timeperiod)=lostUpdatePreventionTZ) THEN
    RAISE EXCEPTION 'Unable to update klassifikation with uuid [%], as the klassifikation seems to have been updated since latest read by client (the given lostUpdatePreventionTZ [%] does not match the timesamp of latest registration [%]).',klassifikation_uuid,lostUpdatePreventionTZ,LOWER((prev_klassifikation_registrering.registrering).timeperiod);
  END IF;   
END IF;

--handle relationer (relations)


--1) Insert relations given as part of this update
--2) Insert relations of previous registration, taking overlapping virknings into consideration (using function subtract_tstzrange)

--Ad 1)



    INSERT INTO klassifikation_relation (
      klassifikation_registrering_id,
        virkning,
          rel_maal,
            rel_type
    )
    SELECT
      new_klassifikation_registrering.id,
        a.virkning,
          a.relMaal,
            a.relType
    FROM unnest(relationer) as a
  ;

 
--Ad 2)

/**********************/
-- 0..1 relations 

FOREACH klassifikation_relation_navn in array  ARRAY['ansvarlig'::KlassifikationRelationKode,'ejer'::KlassifikationRelationKode]
LOOP

  INSERT INTO klassifikation_relation (
      klassifikation_registrering_id,
        virkning,
          rel_maal,
            rel_type
    )
  SELECT 
      new_klassifikation_registrering.id, 
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
    FROM klassifikation_relation b
    WHERE 
          b.klassifikation_registrering_id=new_klassifikation_registrering.id
          and
          b.rel_type=klassifikation_relation_navn
  ) d
  JOIN klassifikation_relation a ON true
  JOIN unnest(_subtract_tstzrange_arr((a.virkning).TimePeriod,tzranges_of_new_reg)) as c(tz_range_leftover) on true
  WHERE a.klassifikation_registrering_id=prev_klassifikation_registrering.id 
        and a.rel_type=klassifikation_relation_navn 
  ;
END LOOP;

/**********************/
-- 0..n relations

--The question regarding how the api-consumer is to specify the deletion of 0..n relation already registered is not answered.
--The following options presents itself:
--a) In this special case, the api-consumer has to specify the full set of the 0..n relation, when updating 
-- ref: ("Hvis indholdet i en liste af elementer rettes, skal hele den nye liste af elementer med i ObjektRet - p27 "Generelle egenskaber for serviceinterfaces på sags- og dokumentområdet")

--Assuming option 'a' above is selected, we only have to check if there are any of the relations with the given name present in the new registration, otherwise copy the ones from the previous registration


FOREACH klassifikation_relation_navn in array ARRAY[]
LOOP

  IF NOT EXISTS  (SELECT 1 FROM klassifikation_relation WHERE klassifikation_registrering_id=new_klassifikation_registrering.id and rel_type=klassifikation_relation_navn) THEN

    INSERT INTO klassifikation_relation (
          klassifikation_registrering_id,
            virkning,
              rel_maal,
                rel_type
        )
    SELECT 
          new_klassifikation_registrering.id,
            virkning,
              rel_maal,
                rel_type
    FROM klassifikation_relation
    WHERE klassifikation_registrering_id=prev_klassifikation_registrering.id 
    and rel_type=klassifikation_relation_navn 
    ;

  END IF;
            
END LOOP;
/**********************/
-- handle tilstande (states)

--1) Insert tilstande/states given as part of this update
--2) Insert tilstande/states of previous registration, taking overlapping virknings into consideration (using function subtract_tstzrange)

/********************************************/
--klassifikation_tils_publiceret
/********************************************/

--Ad 1)

INSERT INTO klassifikation_tils_publiceret (
        virkning,
          publiceret,
            klassifikation_registrering_id
) 
SELECT
        a.virkning,
          a.publiceret,
            new_klassifikation_registrering.id
FROM
unnest(tilsPubliceret) as a
;
 

--Ad 2

INSERT INTO klassifikation_tils_publiceret (
        virkning,
          publiceret,
            klassifikation_registrering_id
)
SELECT 
        ROW(
          c.tz_range_leftover,
            (a.virkning).AktoerRef,
            (a.virkning).AktoerTypeKode,
            (a.virkning).NoteTekst
        ) :: virkning,
          a.publiceret,
            new_klassifikation_registrering.id
FROM
(
 --build an array of the timeperiod of the virkning of the klassifikation_tils_publiceret of the new registrering to pass to _subtract_tstzrange_arr on the klassifikation_tils_publiceret of the previous registrering 
    SELECT coalesce(array_agg((b.virkning).TimePeriod),array[]::TSTZRANGE[]) tzranges_of_new_reg
    FROM klassifikation_tils_publiceret b
    WHERE 
          b.klassifikation_registrering_id=new_klassifikation_registrering.id
) d
  JOIN klassifikation_tils_publiceret a ON true  
  JOIN unnest(_subtract_tstzrange_arr((a.virkning).TimePeriod,tzranges_of_new_reg)) as c(tz_range_leftover) on true
  WHERE a.klassifikation_registrering_id=prev_klassifikation_registrering.id     
;


/**********************/
--Handle attributter (attributes) 

/********************************************/
--klassifikation_attr_egenskaber
/********************************************/

--Generate and insert any merged objects, if any fields are null in attrKlassifikationObj
IF attrEgenskaber IS NOT null THEN
  FOREACH attrEgenskaberObj in array attrEgenskaber
  LOOP

  --To avoid needless fragmentation we'll check for presence of null values in the fields - and if none are present, we'll skip the merging operations
  IF (attrEgenskaberObj).brugervendtnoegle is null OR 
   (attrEgenskaberObj).beskrivelse is null OR 
   (attrEgenskaberObj).kaldenavn is null OR 
   (attrEgenskaberObj).ophavsret is null 
  THEN

  INSERT INTO
  klassifikation_attr_egenskaber
  (
    brugervendtnoegle,beskrivelse,kaldenavn,ophavsret
    ,virkning
    ,klassifikation_registrering_id
  )
  SELECT 
    coalesce(attrEgenskaberObj.brugervendtnoegle,a.brugervendtnoegle), 
    coalesce(attrEgenskaberObj.beskrivelse,a.beskrivelse), 
    coalesce(attrEgenskaberObj.kaldenavn,a.kaldenavn), 
    coalesce(attrEgenskaberObj.ophavsret,a.ophavsret),
	ROW (
	  (a.virkning).TimePeriod * (attrEgenskaberObj.virkning).TimePeriod,
	  (attrEgenskaberObj.virkning).AktoerRef,
	  (attrEgenskaberObj.virkning).AktoerTypeKode,
	  (attrEgenskaberObj.virkning).NoteTekst
	)::Virkning,
    new_klassifikation_registrering.id
  FROM klassifikation_attr_egenskaber a
  WHERE
    a.klassifikation_registrering_id=prev_klassifikation_registrering.id 
    and (a.virkning).TimePeriod && (attrEgenskaberObj.virkning).TimePeriod
  ;

  --For any periods within the virkning of the attrEgenskaberObj, that is NOT covered by any "merged" rows inserted above, generate and insert rows

  INSERT INTO
  klassifikation_attr_egenskaber
  (
    brugervendtnoegle,beskrivelse,kaldenavn,ophavsret
    ,virkning
    ,klassifikation_registrering_id
  )
  SELECT 
    attrEgenskaberObj.brugervendtnoegle, 
    attrEgenskaberObj.beskrivelse, 
    attrEgenskaberObj.kaldenavn, 
    attrEgenskaberObj.ophavsret,
	  ROW (
	       b.tz_range_leftover,
	      (attrEgenskaberObj.virkning).AktoerRef,
	      (attrEgenskaberObj.virkning).AktoerTypeKode,
	      (attrEgenskaberObj.virkning).NoteTekst
	  )::Virkning,
    new_klassifikation_registrering.id
  FROM
  (
  --build an array of the timeperiod of the virkning of the klassifikation_attr_egenskaber of the new registrering to pass to _subtract_tstzrange_arr 
      SELECT coalesce(array_agg((b.virkning).TimePeriod),array[]::TSTZRANGE[]) tzranges_of_new_reg
      FROM klassifikation_attr_egenskaber b
      WHERE 
       b.klassifikation_registrering_id=new_klassifikation_registrering.id
  ) as a
  JOIN unnest(_subtract_tstzrange_arr((attrEgenskaberObj.virkning).TimePeriod,a.tzranges_of_new_reg)) as b(tz_range_leftover) on true
  ;

  ELSE
    --insert attrEgenskaberObj raw (if there were no null-valued fields) 

    INSERT INTO
    klassifikation_attr_egenskaber
    (
    brugervendtnoegle,beskrivelse,kaldenavn,ophavsret
    ,virkning
    ,klassifikation_registrering_id
    )
    VALUES ( 
    attrEgenskaberObj.brugervendtnoegle, 
    attrEgenskaberObj.beskrivelse, 
    attrEgenskaberObj.kaldenavn, 
    attrEgenskaberObj.ophavsret,
    attrEgenskaberObj.virkning,
    new_klassifikation_registrering.id
    );

  END IF;

  END LOOP;
END IF;

--Handle egenskaber of previous registration, taking overlapping virknings into consideration (using function subtract_tstzrange)

INSERT INTO klassifikation_attr_egenskaber (
    brugervendtnoegle,beskrivelse,kaldenavn,ophavsret
    ,virkning
    ,klassifikation_registrering_id
)
SELECT
      a.brugervendtnoegle,
      a.beskrivelse,
      a.kaldenavn,
      a.ophavsret,
	  ROW(
	    c.tz_range_leftover,
	      (a.virkning).AktoerRef,
	      (a.virkning).AktoerTypeKode,
	      (a.virkning).NoteTekst
	  ) :: virkning,
	 new_klassifikation_registrering.id
FROM
(
 --build an array of the timeperiod of the virkning of the klassifikation_attr_egenskaber of the new registrering to pass to _subtract_tstzrange_arr on the klassifikation_attr_egenskaber of the previous registrering 
    SELECT coalesce(array_agg((b.virkning).TimePeriod),array[]::TSTZRANGE[]) tzranges_of_new_reg
    FROM klassifikation_attr_egenskaber b
    WHERE 
          b.klassifikation_registrering_id=new_klassifikation_registrering.id
) d
  JOIN klassifikation_attr_egenskaber a ON true  
  JOIN unnest(_subtract_tstzrange_arr((a.virkning).TimePeriod,tzranges_of_new_reg)) as c(tz_range_leftover) on true
  WHERE a.klassifikation_registrering_id=prev_klassifikation_registrering.id     
;


/******************************************************************/
--If the new registrering is identical to the previous one, we need to throw an exception to abort the transaction. 

read_new_klassifikation:=as_read_klassifikation(klassifikation_uuid, (new_klassifikation_registrering.registrering).timeperiod,null);
read_prev_klassifikation:=as_read_klassifikation(klassifikation_uuid, (prev_klassifikation_registrering.registrering).timeperiod ,null);
 
 /*
read_new_klassifikation_reg klassifikationRegistreringType;
read_prev_klassifikation_reg klassifikationRegistreringType;
*/

--the ordering in as_list (called by as_read) ensures that the latest registration is returned at index pos 1

/*
--TODO
IF NOT (read_new_klassifikation.registrering[1].registrering=new_klassifikation_registrering AND read_prev_klassifikation.registrering[1].registrering=prev_klassifikation_registrering) THEN
  RAISE EXCEPTION 'Error updating klassifikation with id [%]: The ordering of as_list_klassifikation should ensure that the latest registrering can be found at index 1. Expected new reg: [%]. Actual new reg at index 1: [%]. Expected prev reg: [%]. Actual prev reg at index 1: [%].  ',klassifikation_uuid,to_json(new_klassifikation_registrering),to_json(read_new_klassifikation.registrering[1].registrering),to_json(prev_klassifikation_registrering),to_json(prev_new_klassifikation.registrering[1].registrering);
END IF;
 */
 --we'll ignore the registreringBase part in the comparrison - except for the livcykluskode

read_new_klassifikation_reg:=ROW(
ROW(null,(read_new_klassifikation.registrering[1].registrering).livscykluskode,null,null)::registreringBase,
(read_new_klassifikation.registrering[1]).tilsPubliceret ,
(read_new_klassifikation.registrering[1]).attrEgenskaber ,
relationer 
)::klassifikationRegistreringType
;

read_prev_klassifikation_reg:=ROW(
ROW(null,(read_prev_klassifikation.registrering[1].registrering).livscykluskode,null,null)::registreringBase,
(read_prev_klassifikation.registrering[1]).tilsPubliceret ,
(read_prev_klassifikation.registrering[1]).attrEgenskaber ,
relationer 
)::klassifikationRegistreringType
;


IF read_prev_klassifikation_reg=read_new_klassifikation_reg THEN
  RAISE EXCEPTION 'Aborted updating klassifikation with id [%] as the given data, does not give raise to a new registration. Aborted reg:[%], previous reg:[%]',klassifikation_uuid,to_json(read_new_klassifikation_reg),to_json(read_prev_klassifikation_reg) USING ERRCODE = 22000;
END IF;

/******************************************************************/


return new_klassifikation_registrering.id;



END;
$$ LANGUAGE plpgsql VOLATILE;





