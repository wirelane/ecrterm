class NotEnoughData(Exception):
    """Raised if the APDU has not enough data to make sense."""


class ZVTException(Exception):
    """Base exception for ZVT errors."""


class TransportLayerException(ZVTException):
    pass


class TransportTimeoutException(TransportLayerException):
    pass


class ApplicationLayerException(ZVTException):
    pass


class TransmissionException(ApplicationLayerException):
    pass
