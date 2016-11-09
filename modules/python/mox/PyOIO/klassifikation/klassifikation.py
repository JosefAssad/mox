#!/usr/bin/env python

from PyOIO.OIOCommon import Virkning, OIOEntity, OIORegistrering, InvalidOIOException, requires_load
from PyOIO.OIOCommon import OIOEgenskab, OIOEgenskabContainer


class Klassifikation(OIOEntity):
    """Represents the OIO information model 1.1 Klassifikation
    https://digitaliser.dk/resource/991439
    """

    ENTITY_CLASS = 'Klassifikation'
    EGENSKABER_KEY = 'klassifikationegenskaber'
    GYLDIGHED_KEY = 'klassifikationgyldighed'

    def __init__(self, lora, id):
        """ Args:
        lora:   Lora - the Lora handler object
        ID:     string - the GUID uniquely representing the Klasse
        """
        super(Klassifikation, self).__init__(lora, id)

    @staticmethod
    def basepath():
        return "/klassifikation/klassifikation"


@Klassifikation.registrering_class
class KlassifikationRegistrering(OIORegistrering):

    @property
    def kaldenavn(self):
        return self.get_egenskab('kaldenavn')

    @property
    def name(self):
        return self.kaldenavn

    @property
    def beskrivelse(self):
        return self.get_egenskab('beskrivelse')

    @property
    def ophavsret(self):
        return self.get_egenskab('ophavsret')


@Klassifikation.egenskab_class
class KlassifikationEgenskab(OIOEgenskab):

    def __init__(self, registrering, data):
        super(KlassifikationEgenskab, self).__init__(registrering, data)
        self.kaldenavn = data.get('kaldenavn')
        self.beskrivelse = data.get('beskrivelse')
        self.ophavsret = data.get('ophavsret')

    @property
    def name(self):
        return self.klassenavn