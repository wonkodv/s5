"""
    Registry of different accessors
"""
import pathlib
from .. import BaseRegistry


class ItemAccessorRegistry(BaseRegistry):

    def __init__(self, path, package):
        super().__init__(path, package)

        self.registered_accessors = {}

    def registerAccessor(self, cls):
        t = cls.TYPE
        self.registered_accessors[t] = cls

    def getAccessorForType(self, typ):
        self.ensureLoaded()
        try:
            return self.registered_accessors[typ]
        except KeyError:
            pass
        # urn:x-s5:file(text/plain)"
        typ, _, _ = typ.partition("(")
        return self.registered_accessors[typ]


Accessors = ItemAccessorRegistry(pathlib.Path(__file__).parent, __package__)
