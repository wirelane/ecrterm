"""Classes and Functions which deal with the APDU Layer."""

from typing import TypeVar, Type
from collections import OrderedDict

from .fields import *
from .bitmaps import BITMAPS

# Currencies
CC_EUR = '0978'
# Command Classes
CMD_STD = 0x6  # all standard commands, mostly ecr to pt
CMD_SERVICE = 0x8  # commands mostly for service. mostly ecr to pt.
CMD_PT = 0x4  # commands from pt to ecr.
CMD_STATUS = 0x5  # only seen in 05 01 : status inquiry.
# from pt to ecr only:
CMD_RESP_OK = 0x80  # work done
CMD_RESP_ERROR = 0x84  # work had errors


class FieldContainer(type):
    @classmethod
    def __prepare__(mcs, name, bases):
        return OrderedDict()

    def __new__(cls, name, bases, classdict):
        retval = super().__new__(cls, name, bases, classdict)
        retval.FIELDS = OrderedDict()
        for supercls in reversed(bases):
            if hasattr(supercls, 'FIELDS'):
                retval.FIELDS.update((k, v) for (k, v) in supercls.FIELDS.items())
        retval.FIELDS.update((k, v) for (k, v) in classdict.items() if isinstance(v, Field))

        have_optional = False
        for k, v in retval.FIELDS.items():
            if v.required:
                if have_optional:
                    raise TypeError("Cannot include required field {} after optional fields".format(k))
            else:
                if not v.ignore_parse_error:
                    have_optional = True

        return retval


APDUType = TypeVar('APDUType', bound='APDU')


class APDU(metaclass=FieldContainer):
    AUTOMATIC_SUBCLASS = True

    REQUIRED_BITMAPS = []
    ALLOWED_BITMAPS = None  # None == all

    def __init__(self, *args, **kwargs):
        self._values = {}
        self._bitmaps = OrderedDict()

        for (name, field), arg in zip(self.FIELDS.items(), args):
            setattr(self, name, arg)
        for name, arg in kwargs.items():
            setattr(self, name, arg)

    def as_dict(self):
        return OrderedDict(self.items())

    def items(self):
        return \
            [(name, getattr(self, name)) for (name, field) in self.FIELDS.items() if field in self._values] + \
            [(name, getattr(self, name)) for name in self._bitmaps.keys()]

    def __repr__(self):
        reps = [
            (
                k,
                self.FIELDS[k].represent(v) if k in self.FIELDS
                else BITMAPS[self._bitmaps[k]][0].represent(v) if k in self._bitmaps
                else "{!r}".format(v)
            )
            for (k, v) in self.items()
        ]
        return "{}({})".format(
            self.__class__.__name__,
            ", ".join(
                "{}={}".format(k, v)
                for (k, v) in reps
            )
        )

    def __getattr__(self, item):
        bmp = self._bitmaps.get(item, None)

        if bmp is None:
            for key, (field, name, description) in BITMAPS.items():
                if item == name:
                    self._bitmaps[name] = key
                    bmp = key

        if bmp is None:
            raise AttributeError("{!r} object has no attribute {!r}".format(self.__class__.__name__, item))

        return BITMAPS[bmp][0].__get__(self)

    def __delattr__(self, item):
        bmp = self._bitmaps.get(item, None)

        if bmp is not None:
            BITMAPS[bmp][0].__delete__(self)

        super().__delattr__(item)

    def __setattr__(self, item, value):
        if item.startswith('_') or item == "FIELDS" or item in self.FIELDS:
            object.__setattr__(self, item, value)
            return

        bmp = self._bitmaps.get(item, None)

        if bmp is None:
            for key, (field, name, description) in BITMAPS.items():
                if item == name:
                    self._bitmaps[name] = key
                    bmp = key

        if bmp is not None:
            if self.ALLOWED_BITMAPS is not None and BITMAPS[bmp][1] not in self.ALLOWED_BITMAPS:
                raise AttributeError("Bitmap {:02X} not allowed on {}".format(bmp, self))
            BITMAPS[bmp][0].__set__(self, value)
        else:
            super().__setattr__(item, value)

    @staticmethod
    def compute_length_field(l: int) -> bytes:
        if l < 255:
            return bytes([l])
        if l < 256 * 256 - 1:
            return bytes([0xff, l & 0xff, (l >> 8) & 0xff])
        raise ValueError

    @classmethod
    def _iterate_subclasses(cls):
        for clazz in cls.__subclasses__():
            yield from clazz._iterate_subclasses()
        yield cls

    @classmethod
    def can_parse(cls, data: Union[bytes, List[int]]) -> bool:
        return True

    def parser_hook(self, data: Union[bytes, List[int]]) -> Union[bytes, List[int]]:
        return data

    @classmethod
    def parse(cls: Type[APDUType], data: Union[bytes, List[int]]) -> APDUType:
        data = bytes(data)
        # Find more appropriate subclass and use that
        if cls.AUTOMATIC_SUBCLASS:
            for clazz in cls._iterate_subclasses():
                if clazz.can_parse(data) and clazz is not cls:
                    return clazz.parse(data)

        retval = cls()

        if len(data) >= 2:
            retval.control_field = bytearray(data[:2])
            data = data[2:]

        length, data = data[0], data[1:]
        if length == 0xff:
            length, data = data[0] + (data << 8), data[2:]

        data = data[:length]

        data = retval.parser_hook(data)

        for name, field in retval.FIELDS.items():
            if not data:
                break
            try:
                value, data = field.parse(data)
            except ParseError:
                if field.ignore_parse_error:
                    continue
                else:
                    raise
            setattr(retval, name, value)

        # Try to parse the remainder as bitmaps
        while len(data):
            key = data[0]
            field, name, description = BITMAPS.get(key, (None, None, None))
            if field is None:
                raise ParseError("Invalid bitmap 0x{:02X}".format(key))
            value, data = field.parse(data[1:])
            setattr(retval, name, value)

        # FIXME Mandatory fields.
        return retval

    def serialize(self) -> bytes:
        data = bytearray()
        for name, field in self.FIELDS.items():
            # FIXME: Mandatory fields.  Esp. in conjunction with bitmaps (defaults?)
            d = getattr(self, name)
            if d is not None:
                data.extend(field.serialize(d))
        for name, key in self._bitmaps.items():
            d = getattr(self, name)
            if d is not None:
                data.append(key)
                data.extend(BITMAPS[key][0].serialize(d))
        return bytes(self.control_field) + self.compute_length_field(len(data)) + data


# FIXME Command vs. response vs. packet
# Is everything a CommandAPDU?

class CommandAPDU(APDU):
    CMD_CLASS = None
    CMD_INSTR = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.control_field = [self.CMD_CLASS, self.CMD_INSTR]

    @classmethod
    def can_parse(cls, data: Union[bytes, List[int]]) -> bool:
        data = bytes(data)
        return len(data) >= 2 and (
            cls.CMD_CLASS is Ellipsis or cls.CMD_CLASS == data[0]
        ) and (
            cls.CMD_INSTR is Ellipsis or cls.CMD_INSTR == data[1]
        )

    @property
    def cmd_class(self):
        return self.control_field[0]

    @cmd_class.setter
    def cmd_class(self, v):
        self.control_field[0] = v

    @property
    def cmd_instr(self):
        return self.control_field[1]

    @cmd_instr.setter
    def cmd_instr(self, v):
        self.control_field[1] = v


class ResponseAPDU(APDU):
    RESP_CCRC = None
    RESP_APRC = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.control_field = [self.RESP_CCRC, self.RESP_APRC]

    def can_parse(cls, data: Union[bytes, List[int]]) -> bool:
        data = bytes(data)
        return len(data) >= 2 and (
            cls.RESP_CCRC is Ellipsis or cls.RESP_CCRC == data[0]
        ) and (
            cls.RESP_APRC is Ellipsis or cls.RESP_APRC == data[1]
        )

    @property
    def resp_ccrc(self):
        return self.control_field[0]

    @resp_ccrc.setter
    def resp_ccrc(self, v):
        self.control_field[0] = v

    @property
    def resp_aprc(self):
        return self.control_field[1]

    @resp_aprc.setter
    def resp_aprc(self, v):
        self.control_field[1] = v


