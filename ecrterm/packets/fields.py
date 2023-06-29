import string
from enum import Enum
from typing import Any, Union, List, Optional, Tuple

from .context import CurrentContext
from .text_encoding import encode, decode
from .tlv import TLV, TLVDictionary, ContainerType
from .types import CharacterSet, VendorQuirks, CardholderIdentification, OnlineTag


class ParseError(Exception):
    pass


class Endianness(Enum):
    BIG_ENDIAN = 3210
    LITTLE_ENDIAN = 123


class Field:
    REPR_FORMAT = "{!r}"
    DATA_TYPE = None

    def __init__(self, required=True, ignore_parse_error=False, data_type=None, name=None, *args, **kwargs):
        self.required = required
        self.ignore_parse_error = ignore_parse_error
        self.data_type = data_type or self.DATA_TYPE
        self.name = name  # Only used in TLV
        super().__init__()

    def from_bytes(self, v: Union[bytes, List[int]]) -> Any:
        return v

    def to_bytes(self, v: Any, length: Optional[int] = None) -> bytes:
        return v

    def parse(self, data: Union[bytes, List[int]]) -> Tuple[Any, bytes]:
        raise NotImplementedError  # pragma: no coverage

    def serialize(self, data: Any) -> bytes:
        raise NotImplementedError  # pragma: no coverage

    def coerce(self, data: Any) -> Any:
        if self.data_type:
            return self.data_type(data)
        return data

    def validate(self, data: Any) -> None:
        pass  # pragma: no coverage

    def represent(self, data: Any) -> str:
        return self.REPR_FORMAT.format(data)

    def __set__(self, instance, value: Any):
        v = self.coerce(value)
        instance._values[self] = v

    def __delete__(self, instance):
        del instance._values[self]

    def __get__(self, instance, objtype=None):
        return instance._values.get(self, None)


class FixedLengthField(Field):
    LENGTH = None

    def __init__(self, length=None, *args, **kwargs):
        self.length = length or self.LENGTH
        if self.length is None:
            raise ValueError("Length must be set for fixed length fields")
        super().__init__(*args, **kwargs)

    def parse(self, data: Union[bytes, List[int]]) -> Tuple[Any, bytes]:
        data = bytes(data) if not isinstance(data, bytes) else data
        v, data = data[:self.length], data[self.length:]
        return self.from_bytes(v), data

    def serialize(self, data: Any) -> bytes:
        self.validate(data)
        return self.to_bytes(data, self.length)

    def validate(self, data: Any) -> None:
        if len(self.to_bytes(data)) != self.length:
            raise ValueError("Field must be exactly {} bytes long (got {} bytes)"
                             .format(self.length, len(self.to_bytes(data))))


class LVARField(Field):
    LL = 1

    def parse(self, data: Union[bytes, List[int]]) -> Tuple[Any, bytes]:
        data = bytes(data) if not isinstance(data, bytes) else data
        l = 0
        for i in range(self.LL):
            if (data[i] & 0xF0) != 0xF0 or (data[i] & 0x0F) > 9:
                raise ParseError("L*VAR length header invalid")
            l = (l * 10) + (data[i] & 0x0F)
        data = data[self.LL:]

        v, data = data[:l], data[l:]

        return self.from_bytes(v), data

    def serialize(self, data: Any) -> bytes:
        data = self.to_bytes(data)

        l = len(data)
        if l >= (10 ** self.LL):
            raise ValueError("Data too long for L*VAR field")

        header = bytes(0xF0 | ((l // (10 ** i)) % 10) for i in reversed(range(self.LL)))
        return header + data


class LLVARField(LVARField):
    LL = 2


class LLLVARField(LVARField):
    LL = 3


class IntField(Field):
    LENGTH = None
    ENDIAN = Endianness.BIG_ENDIAN
    DATA_TYPE = int

    def to_bytes(self, v: int, length: Optional[int] = None) -> bytes:
        length = length if length is not None else self.LENGTH
        if length is None:
            raise ValueError("Need to specify length for IntField serialization")

        result = [0] * length
        for i in range(length):
            n, v = v & 0xff, v >> 8
            if self.ENDIAN is Endianness.BIG_ENDIAN:
                result[length - 1 - i] = n
            else:
                result[i] = n

        if v:
            raise ValueError("Value too large to serialize in {} bytes".format(length))

        return bytes(result)

    def from_bytes(self, v: Union[bytes, List[int]]) -> int:
        if self.ENDIAN is Endianness.LITTLE_ENDIAN:
            v = reversed(v)

        result = 0
        for n in v:
            result = (result << 8) | n

        return result


class BytesField(Field):
    DATA_TYPE = bytes

    def parse(self, data: Union[bytes, List[int]]) -> Tuple[str, bytes]:
        return self.from_bytes(data), b''

    def serialize(self, data: str) -> bytes:
        return self.to_bytes(data)


class StringField(BytesField):
    DATA_TYPE = str

    def __init__(self, *args, **kwargs):
        self._character_set = kwargs.pop('character_set', None)
        super().__init__(*args, **kwargs)

    def from_bytes(self, v: Union[bytes, List[int]]) -> str:
        character_set = self._character_set if self._character_set is not None \
            else CurrentContext.get('character_set', CharacterSet.DEFAULT)
        return decode(bytes(v), character_set)

    def to_bytes(self, v: str, length: int = None) -> bytes:
        character_set = self._character_set if self._character_set is not None \
            else CurrentContext.get('character_set', CharacterSet.DEFAULT)
        retval = encode(v, character_set)

        if length:
            if len(retval) != length:
                raise ValueError("String length doesn't match fixed string length")

        return retval


class ByteField(IntField, FixedLengthField):
    LENGTH = 1
    REPR_FORMAT = "0x{:02X}"


class FlagByteField(IntField, FixedLengthField):
    LENGTH = 1

    def __init__(self, *args, **kwargs):
        if not 'data_type' in kwargs:
            raise TypeError("Must specify data_type")
        super().__init__(*args, **kwargs)

    def from_bytes(self, v: Union[bytes, List[int]]) -> Any:
        v = super().from_bytes(v)
        return self.coerce(v)


class BCDVariableLengthField(Field):
    DATA_TYPE = str

    def from_bytes(self, v: Union[bytes, List[int]]) -> str:
        return bytearray(v).hex()

    def to_bytes(self, v: str, length: Optional[int] = None) -> bytes:
        # Note: we need to allow pseudo-tetrades - e.g. for open reservation enquiry (06 23 03 87 FF FF)
        if any(x not in string.hexdigits for x in v):
            raise ValueError("BCD field contents can only be hexdigits")

        if len(v) % 2 != 0:
            v = '0' + v

        return bytes(bytearray.fromhex(v))

    def validate(self, data: str) -> None:
        super().validate(data)
        # Note: we need to allow pseudo-tetrades - e.g. for open reservation enquiry (06 23 03 87 FF FF)
        if any(x not in string.hexdigits for x in data):
            raise ValueError("BCD field contents can only be hexdigits")


class BCDField(BCDVariableLengthField, FixedLengthField):
    DATA_TYPE = str

    def to_bytes(self, v: str, length: Optional[int] = None) -> bytes:
        length = length if length is not None else (self.length if self.length is not None else self.LENGTH)
        if length is None:
            raise ValueError("Must specify length for BCDField")

        if length != len(v) / 2:
            raise ValueError("Value length doesn't match field length")

        return super().to_bytes(v, length)


class PasswordField(BCDField):
    LENGTH = 3


class BCDIntField(BCDField):
    DATA_TYPE = int

    def from_bytes(self, v: Union[bytes, List[int]]) -> int:
        v = super().from_bytes(v)
        return int(v, 10)

    def to_bytes(self, v: int, length: Optional[int] = None) -> bytes:
        length = length if length is not None else (self.length if self.length is not None else self.LENGTH)
        v = str(int(v))
        return super().to_bytes(v.rjust(length * 2, '0'), length)

    def coerce(self, data: Any) -> int:
        if isinstance(data, str):
            return super().coerce(int(data.lstrip('0')))
        return super().coerce(data)

    def validate(self, data: int) -> None:
        super().validate(str(int(data)))


class BEIntField(IntField, FixedLengthField):
    ENDIAN = Endianness.BIG_ENDIAN

    def to_bytes(self, v: int, length: Optional[int] = None) -> bytes:
        length = length if length is not None else (self.length if self.length is not None else self.LENGTH)
        return super().to_bytes(v=v, length=length)


class LLStringField(LLVARField, StringField):
    pass


class LLLStringField(LLLVARField, StringField):
    pass


class TLVField(Field):
    DATA_TYPE = TLV

    def from_bytes(self, v: Union[bytes, List[int]]) -> TLV:
        return TLV(bytes(v))

    def to_bytes(self, v: TLV, length: Optional[int] = None) -> bytes:
        if length is not None:
            raise ValueError("Must not give length for TLV container")
        return v.serialize()

    def parse(self, data: Union[bytes, List[int]]) -> Tuple[TLV, bytes]:
        return TLV.parse(
            data, empty_tag=True,
            dictionary='feig_zvt' if VendorQuirks.FEIG_CVEND in CurrentContext.get('vendor_quirks', set()) else 'zvt')

    def serialize(self, data: TLV) -> bytes:
        return data.serialize()

    def __get__(self, instance, objtype=None) -> TLV:
        if not self in instance._values:
            instance._values[self] = TLV()
            instance._values[self].pending = True
        return super().__get__(instance, objtype)


TLVDictionary.register(
    'zvt', {
        None: BytesField(),
        0x07: StringField(name="text_line"),
        0x08: BCDField(name='receipt', length=2),
        0x14: FlagByteField(name="character_set", data_type=CharacterSet),
        0x15: StringField(name="language_code", character_set=CharacterSet.ASCII_7BIT),
        0x23: ContainerType(name='receipt-numbers'),
        0x1d: BEIntField(name='file_id', length=1),
        0x1e: BEIntField(name='start_position', length=4),
        0x40: BytesField(name='emv_config'),
        0x1f00: BEIntField(name='file_size', length=4),
        0x1f10: FlagByteField(name="cardholder_identification", data_type=CardholderIdentification),
        0x1f11: FlagByteField(name='online_tag', data_type=OnlineTag),
        0x1F17: StringField(name="extended_error_text", character_set=CharacterSet.ZVT_8BIT),
        0x1F40: StringField(name="device_name", character_set=CharacterSet.ASCII_7BIT),
        0x1F41: StringField(name="software_version", character_set=CharacterSet.ASCII_7BIT),
        0x1F42: BCDVariableLengthField(name="serial_number"),
        0x1F43: ByteField(name="device_state"),
        0x1F44: BCDField(name="terminal_identifier", length=4),
        0x1F0E: BCDField(name='date', length=4),
        0x1F0F: BCDField(name='time', length=3),
        0x2f: ContainerType(name="payment_type"),
    }
)

TLVDictionary.child(
    'feig_zvt', 'zvt', {
        0x1F17: StringField(name="extended_error_text", character_set=CharacterSet.UTF8),
        0xFF40: PasswordField(name="service_password"),
        # 1st byte: screensaver-timeout in minutes (0-255), 2nd byte: screensaver-type (0: black, 1: graphics)
        0xFF48: BCDField(name="screensaver_timeout_and_type", length=2),
    }
)
