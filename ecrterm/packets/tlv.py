import string
from enum import IntEnum
from typing import Union, Tuple, TypeVar, Type, List, Dict, Any
from .context import CurrentContext
from .types import VendorQuirks


class TLVClass(IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT = 2
    PRIVATE = 3


TLVItemType = TypeVar('TLVItemType', bound='TLVItem')


class NotProvided:
    def __repr__(self):
        return "NotProvided"


NOT_PROVIDED = NotProvided()


_FIRST_PARAM_TYPE = Union[NotProvided, TLVItemType, List[TLVItemType], Dict[Union[int, str], Any]]


class TLVItem:
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

    def __new__(cls: Type[TLVItemType], constructed_value_: _FIRST_PARAM_TYPE = NOT_PROVIDED, *args, **kwargs):
        if isinstance(constructed_value_, TLVItem):
            return constructed_value_
        return super().__new__(cls)

    def __init__(self, constructed_value_: _FIRST_PARAM_TYPE =NOT_PROVIDED, tag_=None, value_=NOT_PROVIDED, implicit_=False, **kwargs):
        if isinstance(constructed_value_, TLVItem):
            return  # __new__ handled this

        self._constructed = False
        self._class = None
        self._tag = NOT_PROVIDED
        self._value = None
        self._implicit = implicit_

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
                setattr(self, k, v)

    # <editor-fold desc="tag accessors">
    @property
    def tag_(self):
        return self._tag

    @tag_.setter
    def tag_(self, value):
        if self._tag is not NOT_PROVIDED:
            raise TypeError("Cannot change tag after creation")

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
            if isinstance(value, (tuple,list)):
                self._value = []
                for item in value:
                    if isinstance(item, TLVItem):
                        self._value.append(item)
                    elif isinstance(item, (tuple, list)) and len(item) == 2:
                        k, v = item
                        if isinstance(k, int):
                            k = "x{:X}".format(k)
                        setattr(self, k, v)
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
                    item, value = TLVItem.parse(value)
                    self._value.append(item)
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
            target = TLVItem(tag_=tag, implicit_=True)
            self.value_.append(target)

            return self.__getattr__(key)

        raise AttributeError("{} object has no attribute {!r}".format(self.__class__.__name__, key))

    def __setattr__(self, key, value):
        if key.startswith("_") or key.endswith("_") or key in ["parse", "serialize"]:
            return super().__setattr__(key, value)

        tag = None

        if self._constructed:
            if key.startswith('x') and all(e in string.hexdigits for e in key[1:]):
                tag = int(key[1:], 16)
            elif isinstance(key, int):
                tag = key

        if tag is None:
            return super().__setattr__(key, value)

        for item in self.value_:
            if item.tag_ == tag:
                target = item
                target.value_ = value
                break
        else:
            target = TLVItem(tag_=tag, value_=value)
            self.value_.append(target)

    def __repr__(self):
        if self._tag is None:
            tagstr = ""
        else:
            tagstr = "tag_=0x{:02X}, ".format(self._tag)
        return "{}({}value_={!r})".format(
            self.__class__.__name__,
            tagstr,
            self.value_
        )

    def _serialize_value(self) -> bytes:
        if self._value is None:
            return b''

        if not self._constructed:
            return self._value
        else:
            retval = bytearray()
            for item in self._value:
                retval.extend(item.serialize())
            return bytes(retval)

    @classmethod
    def parse(cls: Type[TLVItemType], data: bytes, empty_tag: bool = False) -> Tuple[TLVItemType, bytes]:
        pos = 0

        if empty_tag:
            tag_ = None
        else:
            tag_, pos = cls._read_tlv_tag(data, pos)

        length, pos = cls._read_tlv_length(data, pos)

        value_ = data[pos:(pos+length)]
        pos = pos + length

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

