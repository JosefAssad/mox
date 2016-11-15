from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, SmallInteger, String, DateTime

Base = declarative_base()

class EffectBorder(Base):
    __tablename__ = 'effectborder'

    id = Column(Integer, primary_key=True)
    uuid = Column(String)
    time = Column(DateTime)
    effect_type = Column(SmallInteger)
    object_type = Column(String)

    def __repr__(self):
        return "<EffectBorder(objecttype='%s', uuid='%s', time='%s', type=%d)>" % (self.object_type, self.uuid, unicode(self.time), self.effect_type)
