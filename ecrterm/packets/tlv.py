from enum import IntEnum
import string

from typing import Union, Tuple, TypeVar, Type, List


class TLVClass(IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT = 2
    PRIVATE = 3


def read_tlv_tag(data: bytes, pos: int) -> Tuple[int, int]:
    tag = data[pos]
    pos += 1
    if tag & 0x1f == 0x1f:
        while data[pos] & 0x80:
            tag = (tag << 8) | data[pos]
            pos += 1
        tag = (tag << 8) | data[pos]
        pos += 1
    return tag, pos


def read_tlv_length(data: bytes, pos: int) -> Tuple[int, int]:
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


def make_tlv_tag(tag: int) -> bytes:
    retval = bytearray()
    while tag > 0:
        retval.insert(0, tag & 0xff)
        tag = tag >> 8
    return bytes(retval)


def make_tlv_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    else:
        retval = bytearray()
        while length:
            retval.insert(0, length & 0xff)
            length = length >> 8
        retval.insert(0, 0x80 | len(retval))
        return bytes(retval)


TLVItemType = TypeVar('TLVItemType', bound='TLVItem')
TLVConstructedItemType = TypeVar('TLVConstructedItemType', bound='TLVConstructedItem')
TLVContainerType = TypeVar('TLVContainerType', bound='TLVContainer')


class TLVItem:
    def __init__(self, tag=None, length=None, value=None):
        self._tag = None
        self._constructed = None
        self._class = None
        self.tag = tag
        self.length = length
        self.value = value
        if self.value:
            self.recalculate_length_field()

    def __repr__(self):
        return "{}(tag=0x{:02X}, length={!r}, value={!r})".format(
            self.__class__.__name__,
            self.tag,
            self.length,
            self.value
        )

    @property
    def tag(self) -> int:
        return self._tag

    @tag.setter
    def tag(self, value: int):
        self._tag = value
        if value:
            t = value
            while t > 0xff:
                t >>= 8
            self._constructed = bool(t & 0x20)
            self._class = TLVClass(t >> 6)

    @property
    def constructed(self) -> bool:
        return self._constructed

    @property
    def tlv_class(self) -> TLVClass:
        return self._class

    @classmethod
    def parse_all(cls: Type[TLVItemType], data: bytes) -> List[TLVItemType]:
        retval = []
        pos = 0
        while pos < len(data):

            tag, pos = read_tlv_tag(data, pos)

            length, pos = read_tlv_length(data, pos)

            t = tag
            while t > 0xff:
                t >>= 8
            constructed = bool(t & 0x20)

            clazz = TLVConstructedItem if constructed else TLVItem

            value = data[pos: (pos + length)]

            if constructed:
                value = cls.parse_all(value)

            item = clazz(tag=tag, length=length, value=value)

            pos += item.length

            retval.append(item)

        return retval

    def serialize(self) -> bytes:
        retval = bytearray(make_tlv_tag(self.tag))
        retval.extend(make_tlv_length(self.length))

        if self.constructed:
            for v in self.value:
                retval.extend(v.serialize())
        else:
            retval.extend(self.value)

        return bytes(retval)

    def recalculate_length_field(self):
        if self.constructed:
            for v in self.value:
                v.recalculate_length_field()
            self.length = sum(len(v.serialize()) for v in self.value)
        else:
            self.length = len(self.value)


class ContainerAccessMixin:
    def __getattr__(self, name: str):
        if name.startswith('x') and all(e in string.hexdigits for e in name[1:]):
            tag = int(name[1:], 16)

            for item in self.value:
                if item.tag == tag:
                    if isinstance(item, ContainerAccessMixin):
                        return item
                    return item.value

            raise KeyError("Tag {:02X} not found".format(tag))


class TLVConstructedItem(ContainerAccessMixin, TLVItem):
    def __repr__(self):
        return "{}(tag=0x{:02X}, length={!r}, value={!r})".format(
            self.__class__.__name__,
            self.tag,
            self.length,
            self.value
        )

class TLVContainer(ContainerAccessMixin):
    def __new__(cls, value: Union[List[TLVItem], TLVContainerType], *args, **kwargs):
        if isinstance(value, TLVContainer):
            return value
        return super().__new__(cls)

    def __init__(self, value: Union[List[TLVItem], TLVContainerType]):
        if isinstance(value, TLVContainer):
            # Was handled by __new__
            return
        self.value = value

    def __repr__(self):
        return "{}({!r})".format(self.__class__.__name__, self.value)

    def to_bytes(self) -> bytes:
        retval = bytearray()
        for v in self.value:
            v.recalculate_length_field()
            retval.extend(v.serialize())
        return bytes(retval)

    @classmethod
    def from_bytes(cls: Type[TLVContainerType], data: bytes) -> TLVContainerType:
        values = TLVItem.parse_all(data)
        return cls(values)

    def serialize(self) -> bytes:
        d = self.to_bytes()
        return bytes(make_tlv_length(len(d))) + d

    @classmethod
    def parse(cls: Type[TLVContainerType], data: bytes) -> Tuple[TLVContainerType, bytes]:
        length, pos = read_tlv_length(data, 0)
        return cls.from_bytes(data[pos:(pos+length)]), data[(pos+length):]
