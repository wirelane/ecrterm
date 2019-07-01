from typing import Union

from .types import CharacterSet

# "7-bit ASCII with umlauts"
# Note that this not a "CharacterSet" member, but explicitly used for some fields
ZVT_7BIT_CHARACTER_SET = [
    chr(i) for i in range(128)
]
ZVT_7BIT_CHARACTER_SET[0x5B:0x5E] = list('ÄÖÜ')
ZVT_7BIT_CHARACTER_SET[0x7B:0x80] = list('äöüßΔ')


def _map_character_set(encoding: CharacterSet):
    if encoding is CharacterSet.ASCII_7BIT:
        return 'ascii'
    elif encoding is CharacterSet.UTF8:
        return 'utf-8'
    elif encoding is CharacterSet.CP437:
        return 'cp437'
    else:
        return 'iso-8859-{}'.format(encoding.value)


def encode(value: str, encoding: Union[list, CharacterSet] = CharacterSet.DEFAULT) -> bytes:
    if encoding is ZVT_7BIT_CHARACTER_SET:
        return bytes(ZVT_7BIT_CHARACTER_SET.index(t) for t in value)
    elif isinstance(encoding, CharacterSet):
        return value.encode(_map_character_set(encoding))
    else:
        raise ValueError("encoding parameter must me a CharacterSet or the special value ZVT_7BIT_CHARACTER_SET")


def decode(value: bytes, encoding: Union[list, CharacterSet] = CharacterSet.DEFAULT) -> str:
    if encoding is ZVT_7BIT_CHARACTER_SET:
        return "".join(ZVT_7BIT_CHARACTER_SET[t & 0x7f] for t in value)
    elif isinstance(encoding, CharacterSet):
        return value.decode(_map_character_set(encoding))
    else:
        raise ValueError("encoding parameter must me a CharacterSet or the special value ZVT_7BIT_CHARACTER_SET")
