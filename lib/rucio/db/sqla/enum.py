# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2017
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

'''
Class to handle enum type with sqlachelmy.
ref. http://techspot.zzzeek.org/2011/01/14/the-enum-recipe/

'''

import uuid

from six import add_metaclass
from sqlalchemy.types import SchemaType, TypeDecorator, Enum

from rucio.common.exception import InvalidType


class EnumSymbol(object):
    """Define a fixed symbol tied to a parent class."""

    def __init__(self, cls_, name, value, description):
        self.cls_ = cls_
        self.name = name
        self.value = value
        self.description = description

    def __reduce__(self):
        """Allow unpickling to return the symbol
        linked to the DeclEnum class."""
        return getattr, (self.cls_, self.name)

    def __iter__(self):
        return iter([self.value, self.description])

    def __repr__(self):
        return "%s" % self.description


class EnumMeta(type):
    """Generate new DeclEnum classes."""

    def __init__(cls, classname, bases, dict_):  # pylint: disable=E0101
        cls._reg = reg = cls._reg.copy()
        cls._syms = syms = cls._syms.copy()
        for k, v in dict_.items():
            if isinstance(v, tuple):
                sym = reg[v[0]] = syms[v[1]] = EnumSymbol(cls, k, *v)
                setattr(cls, k, sym)
        return type.__init__(cls, classname, bases, dict_)

    def __iter__(cls):
        return iter(cls._reg.values())


@add_metaclass(EnumMeta)
class DeclEnum(object):
    """Declarative enumeration."""

    _reg = {}
    _syms = {}

    @classmethod
    def from_string(cls, value):
        try:
            return cls._reg[value]
        except KeyError:
            raise ValueError("Invalid value for %r: %r" % (cls.__name__, value))

    @classmethod
    def from_sym(cls, value):
        try:
            return cls._syms[value.upper()]
        except KeyError:
            raise ValueError("Invalid value for %r: %r" % (cls.__name__, value))

    @classmethod
    def values(cls):
        return list(cls._reg.keys())

    @classmethod
    def db_type(cls, name=None, default=None):
        return DeclEnumType(enum=cls, name=name, default=default)


class DeclEnumType(SchemaType, TypeDecorator):

    def __init__(self, enum, name=None, default=None):
        self.enum = enum
        if name is None:
            self.impl = Enum(*enum.values(), native_enum=False, name='RUCIO_ENUM_' + str(uuid.uuid4())[:6])
        else:
            self.impl = Enum(*enum.values(), native_enum=False, name=name)

    def _set_parent_with_dispatch(self, parent):
        TypeDecorator._set_parent_with_dispatch(self, parent)
        SchemaType._set_parent_with_dispatch(self, parent)

    def copy(self):
        return DeclEnumType(self.enum)

    def process_bind_param(self, value, dialect):
        try:
            if value is None:
                return None
            return value.value
        except AttributeError:
            raise InvalidType('Invalid value/type %s for %s' % (value, self.enum))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return self.enum.from_string(value.strip())
