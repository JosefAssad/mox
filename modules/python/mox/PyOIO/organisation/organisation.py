#!/usr/bin/env python

from PyOIO.OIOCommon import Virkning, OIOEntity, OIORegistrering, InvalidOIOException, requires_load
from PyOIO.OIOCommon import OIOEgenskab, OIOEgenskabContainer


class Organisation(OIOEntity):
    """Represents the OIO information model 1.1 Organisation
    https://digitaliser.dk/resource/991439
    """

    ENTITY_CLASS = 'Organisation'
    EGENSKABER_KEY = 'organisationegenskaber'
    GYLDIGHED_KEY = 'organisationgyldighed'
    basepath = '/organisation/organisation'

    def __init__(self, lora, id):
        """ Args:
        lora:   Lora - the Lora handler object
        ID:     string - the GUID uniquely representing the Organisation
        """
        super(Organisation, self).__init__(lora, id)


@Organisation.registrering_class
class OrganisationRegistrering(OIORegistrering):

    @property
    def organisationsnavn(self):
        return self.get_egenskab('organisationsnavn')

    @property
    def name(self):
        return self.organisationsnavn


@Organisation.egenskab_class
class OrganisationEgenskab(OIOEgenskab):

    def __init__(self, registrering, data):
        super(OrganisationEgenskab, self).__init__(registrering, data)
        self.organisationsnavn = data.get('organisationsnavn')

    @property
    def name(self):
        return self.organisationsnavn