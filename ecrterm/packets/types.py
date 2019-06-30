from enum import IntFlag, IntEnum


class ConfigByte(IntFlag):
    ECR_PRINTS_PAYMENT = 0x02
    ECR_PRINTS_ADMIN = 0x04
    ECR_INTERMEDIATE_STATUS = 0x08
    ECR_CONTROLS_PAYMENT = 0x10
    ECR_CONTROLS_ADMIN = 0x20
    ECR_USE_PRINT_LINES = 0x80

    ALL_BUT_ADMIN_RECEIPT = DEFAULT = 0xba
    ALL = 0xbe


class ServiceByte(IntFlag):
    SERVICE_MENU_NOT_ASSIGNED = 0x01
    USE_CAPITALS = 0x02

    NONE = DEFAULT = 0x00

class CurrencyCode(IntEnum):
    EUR = 978
