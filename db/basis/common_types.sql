-- Copyright (C) 2015 Magenta ApS, http://magenta.dk.
-- Contact: info@magenta.dk.
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

CREATE TYPE AktoerTypeKode AS ENUM (
  'Organisation',
  'OrganisationEnhed',
  'OrganisationFunktion',
  'Bruger',
  'ItSystem',
  'Interessefaellesskab'
);

CREATE TYPE Virkning AS (
  TimePeriod TSTZRANGE,
  AktoerRef UUID,
  AktoerTypeKode AktoerTypeKode,
  NoteTekst TEXT
);

CREATE TYPE LivscyklusKode AS ENUM (
  'Opstaaet',
  'Importeret',
  'Passiveret',
  'Slettet',
  'Rettet'
);

CREATE TYPE RegistreringBase AS --should be renamed to Registrering, when the old 'Registrering'-type is replaced
(
timeperiod tstzrange,
livscykluskode livscykluskode,
brugerref uuid,
note text
);

CREATE TYPE OffentlighedundtagetType AS 
(
AlternativTitel text,
Hjemmel text
);



/****************************************/

CREATE TYPE ClearableInt AS (
  value int,
  cleared boolean
);

CREATE TYPE ClearableDate AS (
  value date,
  cleared boolean
);

CREATE TYPE ClearableBoolean AS (
  value boolean,
  cleared boolean
);



CREATE OR REPLACE FUNCTION actual_state._cast_ClearableInt_to_int( clearable_int ClearableInt) 

RETURNS
int
AS 
$$
DECLARE 
BEGIN

IF clearable_int IS NULL THEN
  RETURN NULL;
ELSE
  RETURN clearable_int.value;
END IF;

END;
$$ LANGUAGE plpgsql immutable;

create cast (ClearableInt as int)  with function actual_state._cast_ClearableInt_to_int(ClearableInt) as implicit; 


CREATE OR REPLACE FUNCTION actual_state._cast_int_to_ClearableInt( int_value int) 

RETURNS
ClearableInt
AS 
$$
DECLARE 
BEGIN

IF int_value IS NULL THEN
  RETURN NULL;
ELSE
  RETURN ROW(int_value,null)::ClearableInt;
END IF;

END;
$$ LANGUAGE plpgsql immutable;

create cast (int as ClearableInt) with function actual_state._cast_int_to_ClearableInt(int) as implicit; 



CREATE OR REPLACE FUNCTION actual_state._cast_text_to_ClearableInt( text_value text) 

RETURNS
ClearableInt
AS 
$$
DECLARE 
BEGIN

IF text_value IS NULL THEN
  RETURN NULL;
ELSE
  IF text_value<>'' THEN 
    RAISE EXCEPTION 'Unable to cast text value [%] to ClearableInt. Only empty text is allowed (or null).',text_value USING ERRCODE = 22000;
  ELSE
    RETURN ROW(null,true)::ClearableInt;
  END IF;
  
END IF;

END;
$$ LANGUAGE plpgsql immutable;

create cast (text as ClearableInt) with function actual_state._cast_text_to_ClearableInt(text) as implicit; 





/**************************************************************************/

CREATE OR REPLACE FUNCTION actual_state._cast_ClearableDate_to_date( clearable_date ClearableDate) 

RETURNS
date
AS 
$$
DECLARE 
BEGIN

IF clearable_date IS NULL THEN
  RETURN NULL;
ELSE
  RETURN clearable_date.value;
END IF;

END;
$$ LANGUAGE plpgsql immutable;


create cast (ClearableDate as date)  with function actual_state._cast_ClearableDate_to_date(ClearableDate) as implicit; 



CREATE OR REPLACE FUNCTION actual_state._cast_date_to_ClearableDate( date_value date) 

RETURNS
ClearableDate
AS 
$$
DECLARE 
BEGIN

IF date_value IS NULL THEN
  RETURN NULL;
ELSE
  RETURN ROW(date_value,null)::ClearableDate;
END IF;

END;
$$ LANGUAGE plpgsql immutable;

create cast (date as ClearableDate) with function actual_state._cast_date_to_ClearableDate(date) as implicit; 




CREATE OR REPLACE FUNCTION actual_state._cast_text_to_ClearableDate( text_value text) 

RETURNS
ClearableDate
AS 
$$
DECLARE 
BEGIN

IF text_value IS NULL THEN
  RETURN NULL;
ELSE
  IF text_value<>'' THEN 
    RAISE EXCEPTION 'Unable to cast text value [%] to ClearableDate. Only empty text is allowed (or null).',text_value USING ERRCODE = 22000;
  ELSE
    RETURN ROW(null,true)::ClearableDate;
  END IF;
  
END IF;

END;
$$ LANGUAGE plpgsql immutable;

create cast (text as ClearableDate) with function actual_state._cast_text_to_ClearableDate(text) as implicit; 




/**************************************************************************/

CREATE OR REPLACE FUNCTION actual_state._cast_ClearableBoolean_to_boolean( clearable_boolean ClearableBoolean) 

RETURNS
boolean
AS 
$$
DECLARE 
BEGIN

IF clearable_boolean IS NULL THEN
  RETURN NULL;
ELSE
  RETURN clearable_boolean.value;
END IF;

END;
$$ LANGUAGE plpgsql immutable;


create cast (ClearableBoolean as boolean)  with function actual_state._cast_ClearableBoolean_to_boolean(ClearableBoolean) as implicit; 



CREATE OR REPLACE FUNCTION actual_state._cast_boolean_to_ClearableBoolean( boolean_value boolean) 

RETURNS
ClearableBoolean
AS 
$$
DECLARE 
BEGIN

IF boolean_value IS NULL THEN
  RETURN NULL;
ELSE
  RETURN ROW(boolean_value,null)::ClearableBoolean;
END IF;

END;
$$ LANGUAGE plpgsql immutable;

create cast (boolean as ClearableBoolean) with function actual_state._cast_boolean_to_ClearableBoolean(boolean) as implicit; 



CREATE OR REPLACE FUNCTION actual_state._cast_text_to_ClearableBoolean( text_value text) 

RETURNS
ClearableBoolean
AS 
$$
DECLARE 
BEGIN

IF text_value IS NULL THEN
  RETURN NULL;
ELSE
  IF text_value<>'' THEN 
    RAISE EXCEPTION 'Unable to cast text value [%] to ClearableBoolean. Only empty text is allowed (or null).',text_value USING ERRCODE = 22000;
  ELSE
    RETURN ROW(null,true)::ClearableBoolean;
  END IF;
  
END IF;

END;
$$ LANGUAGE plpgsql immutable;

create cast (text as ClearableBoolean) with function actual_state._cast_text_to_ClearableBoolean(text) as implicit; 

