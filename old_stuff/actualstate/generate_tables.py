#!/usr/bin/env python
# encoding: utf-8
# Copyright (C) 2015 Magenta ApS, http://magenta.dk.
# Contact: info@magenta.dk.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from string import Template

tables = {
    'Bruger': {
        'atttributes': {
            'Egenskaber': ['BrugervendtNoegle', 'Brugernavn', 'Brugertype'],
        },
        'states': {'Gyldighed': ['Aktiv', 'Inaktiv'] },
        'relations': ['Adresser', 'Brugertyper', 'Opgaver', 'Tilhoerer',
                      'TilknyttedeEnheder', 'TilknyttedeFunktioner',
                      'TilknyttedeInteressefaellesskaber',
                      'TilknyttedeOrganisationer', 'TilknyttedePersoner',
                      'TilknyttedeItSystemer'],
    },
    'Interessefaellesskab': {
        'attributes': {
            'Egenskaber': ['BrugervendtNoegle', 'Interessefaellesskabsnavn',
                           'Interessefaellesskabstype'],
        },
        'states': {'Gyldighed': ['Aktiv', 'Inaktiv'] },
        'relations': ['Adresser', 'Branche', 'Interessefaellesskabstype',
                      'Opgaver', 'Overordnet', 'Tilhoerer',
                      'TilknyttedeBrugere', 'TilknyttedeEnheder',
                      'TilknyttedeFunktioner',
                      'TilknyttedeInteressefaellesskaber',
                      'TilknyttedeOrganisationer', 'TilknyttedePersoner',
                      'TilknyttedeItSystemer'],
    },
    'ItSystem': {
        'attributes': {
            'Egenskaber': ['BrugervendtNoegle', 'ItSystemNavn', 
                           'ItSystemType', 'KonfigurationReference'],
        },
        'states': {'Gyldighed': ['Aktiv', 'Inaktiv'] },
        'relations': ['Tilhoerer', 'TilknyttedeOrganisationer',
                      'TilknyttedeEnheder', 'TilknyttedeFunktioner',
                      'TilknyttedeBrugere',
                      'TilknyttedeInteressefaellesskaber',
                      'TilknyttedeItSystemer', 'TilknyttedePersoner',
                      'Systemtyper', 'Opgaver', 'Adresser'],

    },
    'Organisation': {
        'attributes': {
            'Egenskaber': ['BrugervendtNoegle', 'Organisationsnavn'],
        },
        'states': {'Gyldighed': ['Aktiv', 'Inaktiv'] },
        'relations': ['Adresser', 'Ansatte', 'Branche',
                      'Myndighed', 'Myndighedstype', 'Opgaver', 'Overordnet',
                      'Produktionsenhed', 'Skatteenhed',
                      'Tilhoerer', 'TilknyttedeBruger'
                      'TilknyttedeEnheder', 'TilknyttedeFunktioner',
                      'TilknyttedeInteressefaellesskab',
                      'TilknyttedeOrganisationer', 'TilknyttedePersoner',
                      'TilknyttedeItSystemer',
                      'Virksomhed', 'Virksomhedstype'],
    },
    'OrganisationEnhed': {
        'attributes': {
            'Egenskaber': ['BrugervendtNoegle', 'Enhedsnavn'],
        },
        'states': {'Gyldighed': ['Aktiv', 'Inaktiv'] },
        'relations': ['Adresser', 'Ansatte', 'Branche', 'Enhedstype',
                      'Opgaver', 'Overordnet', 'Produktionsenhed',
                      'Skatteenhed', 'Tilhoerer', 'TilknyttedeBrugere',
                      'TilknyttedeEnheder', 'TilknyttedeFunktioner',
                      'TilknyttedeInteressefaellesskaber',
                      'TilknyttedeOrganisationer', 'TilknyttedePersoner',
                      'TilknyttedeItSystemer'],
    },
    'OrganisationFunktion': {
        'attributes': {
            'BrugervendtNoegle', 
            'Funktionsnavn'
        },
        'states': {'Gyldighed': ['Aktiv', 'Inaktiv'] },
        'relations': [
            'Adresser', 'Opgaver', 'OrganisatoriskFunktionstype',
            'TilknyttedeBrugere', 'TilknyttedeEnheder',
            'TilknyttedeOrganisationer', 'TilknyttedeItSystemer',
            'TilknyttedeInteressefaellesskaber', 'TilknyttedePersoner'],
        },
}

template = Template("""
CREATE TABLE ${table} (PRIMARY KEY (ID)) INHERITS (Objekt);

CREATE TABLE ${table}Registrering  (
  PRIMARY KEY (ID),
  FOREIGN KEY (ObjektID) REFERENCES ${table} (ID),
  -- Exclude overlapping Registrering time periods for the same 'actor' type.
  EXCLUDE USING gist (uuid_to_text(ObjektID) WITH =,
    TimePeriod WITH &&)
) INHERITS (Registrering);


CREATE TABLE ${table}Attributter (
    PRIMARY KEY(ID),
    FOREIGN KEY (RegistreringsID) REFERENCES ${table}Registrering (ID),
    UNIQUE (RegistreringsID, Name)
) INHERITS (Attributter);


CREATE TABLE ${table}Attribut (
    PRIMARY KEY(ID),
    FOREIGN KEY (AttributterID) REFERENCES ${table}Attributter (ID),
    -- Exclude overlapping Virkning time periods within the same Attributter
    EXCLUDE USING gist (AttributterID WITH =,
    composite_type_to_time_range(Virkning) WITH &&)
) INHERITS (Attribut);


CREATE TABLE ${table}AttributFelt (
    PRIMARY KEY(ID),
    FOREIGN KEY (AttributID) REFERENCES ${table}Attribut (ID),
    UNIQUE (AttributID, Name)
) INHERITS (AttributFelt);


CREATE TABLE ${table}Tilstande (
    PRIMARY KEY(ID),
    FOREIGN KEY (RegistreringsID) REFERENCES ${table}Registrering (ID),
    UNIQUE (RegistreringsID, Name)
) INHERITS (Tilstande);


CREATE TABLE ${table}Tilstand (
    PRIMARY KEY(ID),
    FOREIGN KEY (TilstandeID) REFERENCES ${table}Tilstande (ID),
    -- Exclude overlapping Virkning time periods within the same Tilstand
    EXCLUDE USING gist (TilstandeID WITH =,
    composite_type_to_time_range(Virkning) WITH &&)
) INHERITS (Tilstand);


CREATE TABLE ${table}Relationer(
    PRIMARY KEY(ID),
    FOREIGN KEY (RegistreringsID) REFERENCES ${table}Registrering (ID),
    UNIQUE (RegistreringsID, Name)
) INHERITS (Relationer);
    

CREATE TABLE ${table}Relation(
    PRIMARY KEY (ID),
    FOREIGN KEY (RelationerID) REFERENCES ${table}Relationer(ID),
    -- Exclude overlapping Virkning time periods within the same Relation
    EXCLUDE USING gist (RelationerID WITH =,
      composite_type_to_time_range(Virkning) WITH &&)
) INHERITS (Relation);


CREATE TABLE ${table}Reference (
    PRIMARY KEY (ID),
    FOREIGN KEY (RelationID) REFERENCES ${table}Relation(ID) ON DELETE CASCADE,
    -- No duplicates within the same relation!
    UNIQUE (ReferenceID, RelationID)
) INHERITS (Reference);
""")

for table, obj in tables.iteritems():
    print template.substitute({
        'table': table,
        # TODO: Use attribute field names, status values etc. for constraints.
    })

