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
    OVERRIDE_BITMAPS = {}

    def __init__(self, *args, **kwargs):
        self._values = {}
        self._bitmaps = OrderedDict()

        self._KNOWN_BITMAPS = dict(BITMAPS)
        self._KNOWN_BITMAPS.update(self.OVERRIDE_BITMAPS)

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
                else self._KNOWN_BITMAPS[self._bitmaps[k]][0].represent(v) if k in self._bitmaps
                else "{!r}".format(v)
            )
            for (k, v) in self.items() if v is not None
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
            for key, (field, name, description) in self._KNOWN_BITMAPS.items():
                if item == name:
                    self._bitmaps[name] = key
                    bmp = key

        if bmp is None:
            raise AttributeError("{!r} object has no attribute {!r}".format(self.__class__.__name__, item))

        return self._KNOWN_BITMAPS[bmp][0].__get__(self)

    def get(self, name, default=Ellipsis):
        if default is Ellipsis:
            return getattr(self, name)
        else:
            return getattr(self, name, default)

    def __delattr__(self, item):
        bmp = self._bitmaps.get(item, None)

        if bmp is not None:
            self._KNOWN_BITMAPS[bmp][0].__delete__(self)
            del self._bitmaps[item]
        else:
            super().__delattr__(item)

    def __setattr__(self, item, value):
        if item.startswith('_') or item == "FIELDS" or item in self.FIELDS:
            object.__setattr__(self, item, value)
            return

        bmp = self._bitmaps.get(item, None)

        if bmp is None:
            for key, (field, name, description) in self._KNOWN_BITMAPS.items():
                if item == name:
                    self._bitmaps[name] = key
                    bmp = key

        if bmp is not None:
            if self.ALLOWED_BITMAPS is not None and self._KNOWN_BITMAPS[bmp][1] not in self.ALLOWED_BITMAPS:
                raise AttributeError("Bitmap {:02X} not allowed on {}".format(bmp, self))
            self._KNOWN_BITMAPS[bmp][0].__set__(self, value)
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
        return True  # pragma: no cover

    def parser_hook(self, data: Union[bytes, List[int]]) -> Union[bytes, List[int]]:
        return data

    @classmethod
    def parse(cls: Type[APDUType], data: Union[bytes, List[int]]) -> APDUType:
        data = bytes(data)
        hex_data_str = data.hex()
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
            length, data = data[0] + (data[1] << 8), data[2:]

        data = data[:length]

        data = retval.parser_hook(data)
        blacklist = []

        while True:
            try:
                items = retval._parse_inner(data, blacklist)

                if isinstance(items, Field):
                    # The parser has indicated the field it thinks is the problem
                    # Add it to the blacklist and retry
                    blacklist.append(items)
                    continue

                # Parsing seems to have completed without incident
                for k, v in items:
                    setattr(retval, k, v)

                break

            except ParseError as e:
                blacklist_candidates = [
                    f for f in retval.FIELDS.values()
                    if not f.required and f.ignore_parse_error and not f in blacklist
                ]
                if not blacklist_candidates:
                    # No more we can do, probably really a parse error
                    raise ParseError(str(e) + " in data: " + hex_data_str)
                else:
                    blacklist.append(blacklist_candidates[0])
                    continue

        # FIXME Mandatory fields.
        return retval



    def _parse_inner(self, data:bytes, blacklist: List[Field]) -> Union[List[Tuple[str, Any]], Field]:
        # ~~~~ Strategy to parse the SUPER CURSED Completion packet ~~~~
        # A) When a Field parser marked required=False, ignore_parse_error=True fails
        #    it gets added to the blacklist and not tried again
        # B) When something else fails, the first non-blacklisted field parser
        #    marked required=False, ignore_parse_error=True gets added to the blacklist
        #    and the process is started from scratch

        retval = []

        for name, field in self.FIELDS.items():
            if not data:
                break

            if field in blacklist:
                continue

            try:
                value, data = field.parse(data)
            except ParseError:
                if field.ignore_parse_error:
                    # Indicate this field to the outer loop as being problematic
                    return field
                else:
                    raise

            retval.append((name, value))

        # Try to parse the remainder as bitmaps
        while len(data):
            key = data[0]
            field, name, description = self._KNOWN_BITMAPS.get(key, (None, None, None))
            if field is None:
                raise ParseError("Invalid bitmap 0x{:02X}".format(key))
            value, data = field.parse(data[1:])
            retval.append((name, value))

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
                data.extend(self._KNOWN_BITMAPS[key][0].serialize(d))
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
