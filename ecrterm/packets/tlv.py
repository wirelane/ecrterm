import string
from enum import IntEnum
from typing import Union, TypeVar, Type, List, Dict, Tuple, Any, Optional
from .context import CurrentContext, enter_context
from .types import VendorQuirks


class TLVClass(IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT = 2
    PRIVATE = 3


TLVType = TypeVar('TLVType', bound='TLV')


class NotProvided:
    def __repr__(self):
        return "NotProvided"


NOT_PROVIDED = NotProvided()

_FIRST_PARAM_TYPE = Union[
    NotProvided, TLVType, Tuple[Union[TLVType, List, Tuple]], List[Union[TLVType, List, Tuple]], Dict[
        Union[int, str], Any]]


class TLV:
    # <editor-fold desc="static T/L helpers">
    @staticmethod
    def _read_tlv_tag(data: bytes, pos: int) -> Tuple[int, int]:
        tag = data[pos]
        pos += 1
        if tag & 0x1f == 0x1f:
            while data[pos] & 0x80:
                tag = (tag << 8) | data[pos]
                pos += 1
            tag = (tag << 8) | data[pos]
            pos += 1
        return tag, pos

    @staticmethod
    def _read_tlv_length(data: bytes, pos: int) -> Tuple[int, int]:
        if (data[pos] & 0x80) == 0:
            length = data[pos]
            pos += 1
        else:
            ll = data[pos] & 0x7f
            pos += 1
            length = 0
            for i in range(ll):
                length = (length << 8) | data[pos]
                pos += 1
            length = length
        return length, pos

    @staticmethod
    def _make_tlv_tag(tag: int) -> bytes:
        retval = bytearray()
        while tag > 0:
            retval.insert(0, tag & 0xff)
            tag = tag >> 8
        return bytes(retval)

    @staticmethod
    def _make_tlv_length(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        else:
            retval = bytearray()
            while length:
                retval.append(length & 0xff)
                length = length >> 8
            retval.append(0x80 | len(retval))
            return bytes(reversed(retval))

    # </editor-fold>

    def __new__(cls: Type[TLVType], constructed_value_: _FIRST_PARAM_TYPE = NOT_PROVIDED, *args, **kwargs):
        if isinstance(constructed_value_, TLV):
            return constructed_value_
        return super().__new__(cls)

    def __init__(self, constructed_value_: _FIRST_PARAM_TYPE = NOT_PROVIDED, tag_=None, value_=NOT_PROVIDED,
                 implicit_=False, **kwargs):
        if isinstance(constructed_value_, TLV):
            return  # __new__ handled this

        self._constructed = False
        self._class = None
        self._tag = NOT_PROVIDED
        self._value = None
        self._implicit = implicit_
        self._type: Optional[TLVDataType] = None

        self.tag_ = tag_

        if constructed_value_ is not NOT_PROVIDED and value_ is not NOT_PROVIDED:
            raise TypeError("Cannot pass both constructed_value_ and value_")

        if value_ is not NOT_PROVIDED:
            self.value_ = value_
        elif constructed_value_ is not NOT_PROVIDED:
            if not self.constructed_:
                raise TypeError("Tag must be of constructed type to pass constructed_value_")
            self.value_ = constructed_value_

        if kwargs:
            if not self.constructed_:
                raise TypeError("Tag must be of constructed type to pass kwargs")
            for k, v in kwargs.items():
                self.append_(k, v, overwrite=False)

    # <editor-fold desc="tag accessors">
    @property
    def tag_(self):
        return self._tag

    @tag_.setter
    def tag_(self, value):
        if self._tag is not NOT_PROVIDED:
            raise TypeError("Cannot change tag after creation")

        active_dictionary = TLVDictionary.get(CurrentContext.get('tlv_dictionary', 'default'))

        self._tag = value
        self._class = None
        if value is None:
            self._constructed = True
        else:
            t = value
            while t > 0xff:
                t >>= 8
            if VendorQuirks.FEIG_CVEND in CurrentContext.get('vendor_quirks', set()):
                if 0xff00 <= value <= 0xffff:
                    self._constructed = False
                else:
                    self._constructed = bool(t & 0x20)
            else:
                self._constructed = bool(t & 0x20)
            self._class = TLVClass(t >> 6)

        if not self._constructed:
            self._type = active_dictionary.get(value, active_dictionary[None])

    # </editor-fold>

    # <editor-fold desc="constructed/class accessors">
    @property
    def constructed_(self):
        return self._constructed

    @property
    def class_(self):
        return self._class

    # </editor-fold>

    # <editor-fold desc="value accessors">
    @property
    def value_(self):
        if self._value is None and self._constructed:
            self._value = []
        return self._value

    @value_.setter
    def value_(self, value):
        if value is not None:
            self._implicit = False
        if self._constructed:
            if isinstance(value, (tuple, list)):
                self._value = []
                for item in value:
                    if isinstance(item, TLV):
                        self._value.append(item)
                    elif isinstance(item, (tuple, list)) and len(item) == 2:
                        k, v = item
                        if isinstance(k, int):
                            k = "x{:X}".format(k)
                        self.append_(k, v, overwrite=False)
                    else:
                        raise ValueError("Cannot set value {}".format(value))
            elif isinstance(value, dict):
                self._value = []
                for k, v in value.items():
                    if isinstance(k, int):
                        k = "x{:X}".format(k)
                    setattr(self, k, v)
            elif isinstance(value, bytes):
                self._value = []
                while len(value):
                    item, value = TLV.parse(value)
                    self._value.append(item)
        else:
            if self._type:
                self._value = self._type.from_bytes(value)
            else:
                self._value = value

    # </editor-fold>

    def __getattr__(self, key):
        if self._constructed and key.startswith('x') and all(e in string.hexdigits for e in key[1:]):
            tag = int(key[1:], 16)

            for item in self.value_:
                if item.tag_ == tag:
                    if item.constructed_:
                        return item
                    return item.value_

            # Generate an implicit empty tag
            target = TLV(tag_=tag, implicit_=True)
            self.value_.append(target)

            return self.__getattr__(key)

        raise AttributeError("{} object has no attribute {!r}".format(self.__class__.__name__, key))

    def __setattr__(self, key, value):
        if key.startswith("_") or key.endswith("_") or key in ["parse", "serialize"]:
            return super().__setattr__(key, value)

        return self.append_(key, value, overwrite=True)

    def __repr__(self):
        if self._tag is None:
            tagstr = ""
        else:
            tagstr = "tag_=0x{:02X}, ".format(self._tag)
        if self._constructed:
            items = list(self.items_)
            if len(items) != len({e[0] for e in items}):
                valstr = "value_={!r}".format(self.value_)
            else:
                for i, (k, v) in enumerate(items):
                    if isinstance(v, list) and all(isinstance(e, TLV) for e in v):
                        if len(v) == len({e.tag_ for e in v}):
                            items[i] = (k, {e.name_: e.value_ for e in v})
                valstr = ", ".join(
                    "{}={!r}".format(k, v)
                    for (k, v) in items
                )
        else:
            valstr = "value_={!r}".format(self.value_)
        return "{}({}{})".format(
            self.__class__.__name__,
            tagstr,
            valstr
        )

    @property
    def name_(self):
        if self._type and self._type.name:
            return self._type.name
        return "x{:X}".format(self.tag_)

    @property
    def items_(self):
        if not self._constructed:
            raise TypeError("Cannot access items_ of primitive TLV")
        retval = []
        for v in self.value_:
            retval.append((v.name_, v.value_))
        return retval

    def append_(self, key, value, overwrite=False):
        tag = None

        if self._constructed:
            if key.startswith('x') and all(e in string.hexdigits for e in key[1:]):
                tag = int(key[1:], 16)
            elif isinstance(key, int):
                tag = key

        if tag is None:
            return super().__setattr__(key, value)

        if overwrite:
            for item in self.value_:
                if item.tag_ == tag:
                    target = item
                    target.value_ = value
                    return

        target = TLV(tag_=tag, value_=value)
        self.value_.append(target)

    def _serialize_value(self) -> bytes:
        if self._value is None:
            return b''

        if not self._constructed:
            if self._type:
                return self._type.to_bytes(self._value)
            else:
                return self._value
        else:
            retval = bytearray()
            for item in self._value:
                retval.extend(item.serialize())
            return bytes(retval)

    @classmethod
    def parse(cls: Type[TLVType], data: bytes, empty_tag: bool = False, dictionary: Optional[str] = None) \
            -> Tuple[TLVType, bytes]:
        pos = 0

        if empty_tag:
            tag_ = None
        else:
            tag_, pos = cls._read_tlv_tag(data, pos)

        length, pos = cls._read_tlv_length(data, pos)

        value_ = data[pos:(pos + length)]
        pos = pos + length

        if dictionary is not None:
            with enter_context(tlv_dictionary=dictionary):
                retval = cls(tag_=tag_, value_=value_)
        else:
            retval = cls(tag_=tag_, value_=value_)

        return retval, data[pos:]

    def serialize(self) -> bytes:
        d = self._serialize_value()

        if self._implicit and len(d) == 0:
            return b''

        retval = bytearray()
        if isinstance(self._tag, int):
            retval.extend(self._make_tlv_tag(self._tag))
        retval.extend(self._make_tlv_length(len(d)))

        return bytes(retval) + d

    def get_value(self, key, default=None):
        for item in self.items_:
            if item[0] == key:
                return item[1]
        return default


class TLVDataType:
    name = None

    def __init__(self, name=None, *args, **kwargs):
        if name is not None:
            self.name = name
        super().__init__(*args, **kwargs)

    def from_bytes(self, value: bytes) -> Any:
        raise NotImplementedError

    def to_bytes(self, value: Any) -> bytes:
        raise NotImplementedError


class _TLVDictionary(dict):
    def register(self, name, value):
        self[name] = value

    def child(self, name, parent, value):
        self[name] = dict(self[parent])
        self[name].update(value)


TLVDictionary = _TLVDictionary()


class BytesData(TLVDataType):
    def from_bytes(self, value: bytes) -> bytes:
        return value

    def to_bytes(self, value: bytes) -> bytes:
        return bytes(value)


class ContainerType(TLVDataType):
    pass


TLVDictionary.register(
    'default', {
        None: BytesData(),
    },
)

# FIXME store active dictionary in container
# FIXME Tag value assignment with non-byte data
# FIXME dictionary tag names (set and get)
# FIXME repr with names
# FIXME test items_
