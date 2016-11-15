#!/usr/bin/python
# -*- coding: utf-8 -*-
import os

from agent.amqpclient import MessageListener
from agent.message import NotificationMessage, EffectUpdateMessage
from agent.config import read_properties_files, MissingConfigKeyError
from PyLoRA import Lora
from PyOIO.OIOCommon.exceptions import InvalidOIOException
from PyOIO.organisation import Bruger, Interessefaellesskab, ItSystem, Organisation, OrganisationEnhed, OrganisationFunktion
from PyOIO.klassifikation import Facet, Klasse, Klassifikation
from datetime import datetime
import pytz

import sqlalchemy
from tables import Base, EffectBorder

import threading


DIR = os.path.dirname(os.path.realpath(__file__))

configfile = DIR + "/settings.conf"
config = read_properties_files("/srv/mox/mox.conf", configfile)

class MoxEffectWatcher(object):

    EFFECT_START = EffectUpdateMessage.TYPE_BEGIN
    EFFECT_END = EffectUpdateMessage.TYPE_END
    EFFECT_BOTH = EffectUpdateMessage.TYPE_BOTH

    sleeper_thread = None
    session = None

    def __init__(self):

        try:
            amqp_host = config['moxeffectwatcher.amqp.host']
            amqp_username = config['moxeffectwatcher.amqp.username']
            amqp_password = config['moxeffectwatcher.amqp.password']
            amqp_queue_in = config['moxeffectwatcher.amqp.queue_in']
            amqp_queue_out = config['moxeffectwatcher.amqp.queue_out']

            rest_host = config['moxeffectwatcher.rest.host']
            rest_username = config['moxeffectwatcher.rest.username']
            rest_password = config['moxeffectwatcher.rest.password']

        except KeyError as e:
            raise MissingConfigKeyError(str(e))

        self.accepted_object_types = ['bruger', 'interessefaellesskab', 'itsystem', 'organisation', 'organisationenhed', 'organisationfunktion']

        # self.notification_listener = MessageListener(amqp_username, amqp_password, amqp_host, amqp_queue_in, queue_parameters={'durable': True})
        # self.notification_listener.callback = self.handle_message
        # self.notification_listener.run()

        self.lora = Lora(rest_host, rest_username, rest_password)

        self.db = sqlalchemy.create_engine('sqlite:///effects.db')

    def start(self):
        self.db.connect()

        self.sessionclass = sqlalchemy.orm.sessionmaker(bind=self.db)

        self.begin_session()
        Base.metadata.create_all(self.db)
        # for type in [Bruger, Interessefaellesskab, ItSystem, Organisation, OrganisationEnhed, OrganisationFunktion, Facet, Klasse, Klassifikation]:
        for type in [Bruger, Interessefaellesskab, ItSystem, Organisation, OrganisationEnhed, OrganisationFunktion]:
            uuids = self.lora.get_uuids_of_type(type)
            for uuid in uuids:
                item = self.lora.get_object(uuid, type.ENTITY_CLASS)
                self.update(item)

        self.restart_sleeper_thread()
        self.end_session()

        self.block_for_sleeperthread()
        print "end of program"

    def begin_session(self):
        if self.session is None:
            print "starting session"
            self.session = self.sessionclass()

    def end_session(self):
        if self.session is not None:
            print "ending session"
            self.session.close()
            self.session = None

    def handle_message(self, channel, method, properties, body):
        message = NotificationMessage.parse(properties.headers, body)
        if message:
            print "Got a notification"
            if message.objecttype in self.accepted_object_types:
                print "Object type '%s' accepted" % message.objecttype
                self.begin_session()
                try:
                    item = self.lora.get_object(message.objectid, message.objecttype)
                    if message.lifecyclecode == 'Slettet':
                        print "lifecyclecode is '%s', performing delete" % message.lifecyclecode
                        self.delete(item)
                    else:
                        print "lifecyclecode is '%s', performing update" % message.lifecyclecode
                        self.update(item)
                except InvalidOIOException as e:
                    print e
                self.restart_sleeper_thread()
                self.end_session()
            else:
                print "Object type '%s' rejected" % message.objecttype

    def delete(self, item):
        self.session.query(EffectBorder).filter(uuid=item.id).delete()
        self.session.commit()

    def update(self, item):
        changed = False
        object_type = item.ENTITY_CLASS
        # self.session.query(EffectBorder).filter_by(object_type=object_type, uuid=item.id).delete()
        db_objects = self.session.query(EffectBorder).filter_by(object_type=object_type, uuid=item.id).all()
        if len(db_objects) > 0:
            for db_object in db_objects:
                self.session.delete(db_object)
            changed = True

        effects = self.get_effects(item)
        start_times = [effect.from_time for effect in effects if self.accept_time(effect.from_time)]
        end_times = [effect.to_time for effect in effects if self.accept_time(effect.to_time)]
        for time in start_times:
            effect_type = self.EFFECT_START
            if time in end_times:
                effect_type = self.EFFECT_BOTH
            if self.store(object_type, item.id, time, effect_type):
                changed = True
        for time in end_times:
            if time in start_times:
                continue
            if self.store(object_type, item.id, time, self.EFFECT_END):
                changed = True
        if changed:
            self.session.commit()

    def store(self, objecttype, uuid, time, effect_type):
        time = time.astimezone(pytz.utc)
        print time
        obj = self.session.query(EffectBorder).filter_by(object_type=objecttype, uuid=uuid, time=time).first()
        if obj:
            if obj.type != effect_type:
                obj.type = effect_type
                self.session.add(obj)
                return True
        else:
            obj = EffectBorder(object_type=objecttype, uuid=uuid, time=time, effect_type=effect_type)
            self.session.add(obj)
            return True

    def get_effects(self, item, merge=True):
        effects = []
        for registrering in item.registreringer:
            if hasattr(registrering, 'gyldigheder') and registrering.gyldigheder:
                for gyldighed in registrering.gyldigheder:
                    effects.append(gyldighed.virkning)
            if hasattr(registrering, 'publiceringer') and registrering.publiceringer:
                for publicering in registrering.publiceringer:
                    effects.append(publicering.virkning)
            if registrering.egenskaber:
                for egenskab in registrering.egenskaber:
                    effects.append(egenskab.virkning)
            if registrering.relationer:
                for type,relations in registrering.relationer.items.iteritems():
                    for relation in relations:
                        effects.append(relation.virkning)
        if merge and len(effects) > 1:
            merged = [effects[0]]
            for item in effects:
                match = False
                for existing in merged:
                    if existing.compare_time(item):
                        match = True
                        break
                if not match:
                    merged.append(item)
            return merged
        else:
            return effects

    def get_next_borders(self):
        next_effectborder = self.session.query(EffectBorder).order_by(EffectBorder.time).first()
        return self.session.query(EffectBorder).filter_by(time=next_effectborder.time).all()

    def accept_time(self, time):
        if time.year > 3000:
            return False
        if time < datetime.now(pytz.utc):
            return False
        return True

    # A 'sleeper thread' runs, waiting for a specified time before emitting a notification and then exiting
    # Then the thread is recreated, waiting for another timespan, and so forth
    def restart_sleeper_thread(self):
        print "starting sleeper thread"
        old_thread = self.sleeper_thread
        effectborders = self.get_next_borders()
        if len(effectborders) > 0:
            time = pytz.utc.localize(effectborders[0].time).astimezone(pytz.utc)
            timediff = time - datetime.now(pytz.utc)
            print "should wait for %d seconds" % timediff.total_seconds()
            self.sleeper_thread = threading.Timer(timediff.total_seconds(), self.emit_message)
        else:
            self.sleeper_thread = threading.Timer(24*60*60, self.restart_sleeper_thread)
        self.sleeper_thread.start()
        if old_thread is not None:
            print "stopping old sleeper thread"
            old_thread.cancel()

    # The thread waits until it's time to send a notification about an effect border
    # Then the sleeper thread is restarted
    def emit_message(self):
        print "emit_message"
        self.begin_session()
        effectborders = self.get_next_borders()
        messages = []
        for effectborder in effectborders:
            messages.append(EffectUpdateMessage(effectborder.uuid, effectborder.object_type, effectborder.effect_type, effectborder.time))
            self.session.delete(effectborder)
        self.session.commit()
        print messages
        self.restart_sleeper_thread()
        self.end_session()

    # The main thread must in principle wait forever (until the process is killed)
    # we join() the current sleeper thread, and because another is always ready to take over,
    # we also join() that one
    def block_for_sleeperthread(self):
        while self.sleeper_thread is not None:
            print "waiting for sleeper thread to end"
            try:
                self.sleeper_thread.join()
            except:
                self.sleeper_thread.cancel()
                self.end_session()

main = MoxEffectWatcher()
main.start()