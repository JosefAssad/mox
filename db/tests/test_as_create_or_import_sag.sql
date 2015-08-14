-- Copyright (C) 2015 Magenta ApS, http://magenta.dk.
-- Contact: info@magenta.dk.
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

--SELECT * FROM runtests('test'::name);
CREATE OR REPLACE FUNCTION test.test_as_create_or_import_sag()
RETURNS SETOF TEXT LANGUAGE plpgsql AS 
$$
DECLARE 
	new_uuid1 uuid;
	registrering sagRegistreringType;
	actual_registrering RegistreringBase;
	virkEgenskaber Virkning;
	virkPrimaerklasse Virkning;
	virkSekundaerpart1 Virkning;
	virkSekundaerpart2 Virkning;
	virkAndresager1 Virkning;
	virkAndresager2 Virkning;
	virkPubliceret Virkning;
	sagEgenskab sagEgenskaberAttrType;
	sagFremdrift sagFremdriftTilsType;
	sagRelPrimaerklasse sagRelationType;
	sagRelSekundaerpart1 sagRelationType;
	sagRelSekundaerpart2 sagRelationType;
	sagRelAndresager1 sagRelationType;
	sagRelAndresager2 sagRelationType;
	uuidPrimaerklasse uuid :='f7109356-e87e-4b10-ad5d-36de6e3ee09f'::uuid;
	uuidSekundaerpart1 uuid :='b7160ce6-ac92-4752-9e82-f17d9e1e52ce'::uuid;
	--uuidSekundaerpart2 uuid :='08533179-fedb-4aa7-8902-ab34a219eed9'::uuid;
	urnSekundaerpart2 text:='urn:isbn:0451450523'::text;
	uuidAndresager1 uuid :='f7109356-e87e-4b10-ad5d-36de6e3ee09d'::uuid;
	uuidAndresager2 uuid :='28533179-fedb-4aa7-8902-ab34a219eed1'::uuid;
	uuidRegistrering uuid :='1f368584-4c3e-4ba4-837b-da2b1eee37c9'::uuid;
	actual_publiceret_virk virkning;
	actual_publiceret_value sagFremdriftTils;
	actual_publiceret sagFremdriftTilsType;
	actual_relationer sagRelationType[];
	uuid_to_import uuid :='a1819cce-043b-447f-ba5e-92e6a75df918'::uuid;
	uuid_returned_from_import uuid;
	read_Sag1 SagType;
	expected_sag1 SagType;
BEGIN


virkEgenskaber :=	ROW (
	'[2015-05-12, infinity)' :: TSTZRANGE,
          uuid_generate_v4(),
          'Bruger',
          'NoteEx1'
          ) :: Virkning
;

virkPrimaerklasse :=	ROW (
	'[2015-05-11, infinity)' :: TSTZRANGE,
          uuid_generate_v4(),
          'Bruger',
          'NoteEx2'
          ) :: Virkning
;

virkSekundaerpart1 :=	ROW (
	'[2015-05-10, infinity)' :: TSTZRANGE,
          uuid_generate_v4(),
          'Bruger',
          'NoteEx3'
          ) :: Virkning
;


virkSekundaerpart2 :=	ROW (
	'[2015-05-10, 2016-05-10)' :: TSTZRANGE,
          uuid_generate_v4(),
          'Bruger',
          'NoteEx4'
          ) :: Virkning
;

virkPubliceret := ROW (
	'[2015-05-18, infinity)' :: TSTZRANGE,
          uuid_generate_v4(),
          'Bruger',
          'NoteEx10'
) :: Virkning
;

virkAndresager1 :=	ROW (
	'[2015-04-10, infinity)' :: TSTZRANGE,
          uuid_generate_v4(),
          'Bruger',
          'NoteEx23'
          ) :: Virkning
;


virkAndresager2 :=	ROW (
	'[2015-06-10, 2016-05-10)' :: TSTZRANGE,
          uuid_generate_v4(),
          'Bruger',
          'NoteEx12'
          ) :: Virkning
;

sagRelPrimaerklasse := ROW (
	'ansvarlig'::sagRelationKode
	,virkPrimaerklasse
	,uuidPrimaerklasse
	,null
	,'Klasse'
	,567 --NOTICE: Should be replace in by import function
	,null --relTypeSpec
	,null --journalNotat
	,null --journalDokumentAttr
) :: sagRelationType
;


sagRelSekundaerpart1 := ROW (
	'sekundaerpart'::sagRelationKode,
		virkSekundaerpart1,
	uuidSekundaerpart1,
	null,
	'Person'
	,768 --NOTICE: Should be replace in by import function
	,null --relTypeSpec
	,null --journalNotat
	,null --journalDokumentAttr
) :: sagRelationType
;



sagRelSekundaerpart2 := ROW (
	'sekundaerpart'::sagRelationKode,
		virkSekundaerpart2,
	null,
	urnSekundaerpart2,
	'Person'
	,800 --NOTICE: Should be replace in by import function
	,null --relTypeSpec
	,null --journalNotat
	,null --journalDokumentAttr
) :: sagRelationType
;



sagRelAndresager1 := ROW (
	'andresager'::sagRelationKode,
		virkAndresager1,
	uuidAndresager1,
	null,
	'Person'
	,7268 --NOTICE: Should be replace in by import function
	,null --relTypeSpec
	,null --journalNotat
	,null --journalDokumentAttr
) :: sagRelationType
;



sagRelAndresager2 := ROW (
	'andresager'::sagRelationKode,
		virkAndresager2,
	uuidAndresager2,
	null,
	'Person'
	,3 --NOTICE: Should be replace in by import function
	,null --relTypeSpec
	,null --journalNotat
	,null --journalDokumentAttr
) :: sagRelationType
;

sagFremdrift := ROW (
virkPubliceret,
'Opstaaet'
):: sagFremdriftTilsType
;


sagEgenskab := ROW (
'brugervendtnoegle_sag_1' --text, 
 ,false --'afleveret_sag_1'-- boolean,
,'beskrivelse_sag_1'-- text,
, 'hjemmel_sag_1'-- text,
, 'kassationskode_sag_1'-- text,
,ROW( 
	'alternativTitel_sag_1'
	,'hjemmel_sag_1'
 )::offentlighedundtagettype
, true --principiel boolean,
,'sagsnummer_1' -- text,
, 'titel_sag_1'-- text,
,virkEgenskaber
) :: sagEgenskaberAttrType
;


registrering := ROW (

	ROW (
	NULL,
	'Opstaaet'::Livscykluskode,
	uuidRegistrering,
	'Test Note 4') :: RegistreringBase
	,
ARRAY[sagFremdrift]::sagFremdriftTilsType[],
ARRAY[sagEgenskab]::sagEgenskaberAttrType[],
ARRAY[sagRelPrimaerklasse,sagRelSekundaerpart1,sagRelSekundaerpart2,sagRelAndresager1,sagRelAndresager2]
) :: sagRegistreringType
;


new_uuid1 := as_create_or_import_sag(registrering);

RETURN NEXT ok(true,'No errors running as_create_or_import_sag');


read_Sag1 := as_read_sag(new_uuid1,
	null, --registrering_tstzrange
	null --virkning_tstzrange
	);
--raise notice 'read_Sag1:%',to_json(read_Sag1);

expected_sag1:=ROW(
		new_uuid1,
		ARRAY[
			ROW(
			(read_Sag1.registrering[1]).registrering
			,ARRAY[sagFremdrift]::sagFremdriftTilsType[]
			,ARRAY[sagEgenskab]::sagEgenskaberAttrType[]
			,ARRAY[
				ROW (
						'ansvarlig'::sagRelationKode
						,virkPrimaerklasse
						,uuidPrimaerklasse
						,null
						,'Klasse'
						,null  --NOTICE: Is nulled by import
						,null --relTypeSpec
						,ROW(null,null,null)::JournalNotatType --journalNotat
						,ROW(null, ROW(null,null)::OffentlighedundtagetType) ::JournalPostDokumentAttrType  --journalDokumentAttr
					) :: sagRelationType
				,  ROW (
						'sekundaerpart'::sagRelationKode,
							virkSekundaerpart1,
						uuidSekundaerpart1,
						null,
						'Person'
						,1 
						,null --relTypeSpec
						,ROW(null,null,null)::JournalNotatType 
						,ROW(null, ROW(null,null)::OffentlighedundtagetType) ::JournalPostDokumentAttrType
					) :: sagRelationType
				, 
				ROW (
					'sekundaerpart'::sagRelationKode,
						virkSekundaerpart2,
					null,
					urnSekundaerpart2,
					'Person'
					,2 
					,null --relTypeSpec
					,ROW(null,null,null)::JournalNotatType 
					,ROW(null, ROW(null,null)::OffentlighedundtagetType) ::JournalPostDokumentAttrType --journalDokumentAttr
				) :: sagRelationType
				,
				ROW (
					'andresager'::sagRelationKode,
						virkAndresager1,
					uuidAndresager1,
					null,
					'Person'
					,1 
					,null --relTypeSpec
					,ROW(null,null,null)::JournalNotatType 
					,ROW(null, ROW(null,null)::OffentlighedundtagetType) ::JournalPostDokumentAttrType --journalDokumentAttr
				) :: sagRelationType
				, ROW (
					'andresager'::sagRelationKode,
						virkAndresager2,
					uuidAndresager2,
					null,
					'Person'
					,2 
					,null --relTypeSpec
					,ROW(null,null,null)::JournalNotatType 
					,ROW(null, ROW(null,null)::OffentlighedundtagetType) ::JournalPostDokumentAttrType --journalDokumentAttr
				) :: sagRelationType
				]::SagRelationType[]
			)::SagRegistreringType
			]::SagRegistreringType[]
		)::SagType
;

--raise notice 'expected_sag1:%',to_json(expected_sag1);


RETURN NEXT IS(
	read_Sag1,
	expected_sag1
	,'test create sag #1'
);







END;
$$;