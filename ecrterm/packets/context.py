import threading
import contextlib


_localdata = threading.local()


class Context(dict):
    def __init__(self, _parent=None, **kwargs):
        self._parent = _parent
        self._deleted = set()
        super().__init__(**kwargs)

    def __delitem__(self, key):
        with contextlib.suppress(KeyError):
            super().__delitem__(key)
        self._deleted.add(key)

    def __getitem__(self, key):
        if key in self._deleted:
            raise KeyError("{} deleted in context".format(key))
        if key not in self:
            if self._parent is not None:
                return self._parent[key]
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        if key in self._deleted:
            self._deleted.remove(key)
        super().__setitem__(key, value)


def _get_current_context():
    if not hasattr(_localdata, 'contexts'):
        _localdata.contexts = [Context(_parent=GlobalContext)]
    return _localdata.contexts[-1]


class MetaContext:
    def __delitem__(self, item):
        return _get_current_context().__delitem__(item)

    def __getattribute__(self, key):
        return _get_current_context().__getattribute__(key)

    def __setitem__(self, item, value):
        return _get_current_context().__setitem__(item, value)

    def __getitem__(self, item):
        return _get_current_context().__getitem__(item)


@contextlib.contextmanager
def enter_context(**kwargs):
    _get_current_context()
    _localdata.contexts.append(Context(_parent=_localdata.contexts[-1], **kwargs))
    yield
    _localdata.contexts.pop()


CurrentContext = MetaContext()
GlobalContext = Context()
