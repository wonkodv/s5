"""
    Accessors for items with type
    JSON
    MAP
    LIST
    FILE
"""


import traceback
import warnings
import io
import collections.abc
import json


def Register(registry):
    from s5.client.items import BaseAccessor
    from s5.shared.conventions import ITEM_TYPES

    def RegisteredAccessor(cls):
        registry.registerAccessor(cls)
        return cls

    @RegisteredAccessor
    class JsonAccessor(BaseAccessor):

        """ Store arbitrary Objects encoded as JSON

        Handles dict,list,float,int,string and Boolean

        Dict-Keys are converted to string
          map[25]="value"
          store/load
          map[25] -> KeyError
          map['25'] -> "value"
            """
        TYPE = ITEM_TYPES.JSON

        def __init__(self, item):
            super().__init__(item)
            self.contentLoaded = False
            self.contentUnsaved = False  # save can doe something
            self.contentModified = False  # Content could be lost

        def getDefaultContent(self):
            return None

        def getContent(self):
            if not self.contentLoaded:
                if self.hasContent():
                    b = super().getContentBytes()
                    s = b.decode('UTF-8')
                    j = json.loads(s)
                else:
                    j = self.getDefaultContent()
                    self.contentUnsaved = True
                self.content = j
                self.contentLoaded = True
            return self.content

        def setContent(self, o):
            self.content = o
            self.contentLoaded = True
            self.contentModified = True
            self.contentUnsaved = True

        def touchContent(self):
            self.contentModified = True
            self.contentUnsaved = True

        def beginUpdate(self):
            if self.contentModified:
                warnings.warn(repr(self) + " had unsafed Changes that were "
                              "overwritten by an update")
            self.contentLoaded = False
            self.contentModified = False
            self.contentUnsaved = False

        def __del__(self):
            if self.contentModified:
                warnings.warn(
                    repr(self) +
                    " had unsafed Changes that are lost "
                    "at object disposal",
                    stacklevel=2)

        def save(self):
            if not self.hasContent():
                # Newly created Item, Initialize:
                self.getContent()
            if self.contentUnsaved:
                s = json.dumps(self.content)
                b = s.encode("UTF-8")
                self.saveNewContent(b)
                self.contentModified = False
                self.contentUnsaved = False
            else:
                super().save()

        def childIds(self):
            return ()

        def childIdsWithKeys(self):
            return ()

    @RegisteredAccessor
    class MapAccessor(JsonAccessor, collections.abc.MutableMapping):

        """ Store a Mapping of Name To ItemIDs

        Keys must be strings, otherwise a typeerror is raised.
        JSON would convert and cause inconsistency:
        """

        TYPE = ITEM_TYPES.MAP

        def getDefaultContent(self):
            return dict()

        def putId(self, key, itemId):
            if not isinstance(key, str):
                raise TypeError("Keys must be str, not %s", type(key))
            self.getContent()[key] = itemId
            self.touchContent()

        def getId(self, key):
            if not isinstance(key, str):
                raise TypeError("Keys must be str, not %s", type(key))
            return self.getContent()[key]

        def __len__(self):
            return len(self.getContent())

        def __contains__(self, key):
            return key in self.getContent()

        def __getitem__(self, key):
            itemId = self.getId(key)
            return self.getItemSaver().getItem(itemId)

        def __delitem__(self, key):
            if not isinstance(key, str):
                raise TypeError("Keys must be str, not %s", type(key))
            self.getContent().__delitem__(key)
            self.touchContent()

        def __setitem__(self, key, item):
            self.putId(key, item.getItemId())

        def __iter__(self):
            return self.getContent().__iter__()

        def childIds(self):
            return iter(self.getContent().values())

        def childIdsWithKeys(self):
            c = self.getContent()
            for k in sorted(c.keys()):
                yield k, c[k]

    @RegisteredAccessor
    class ListAccessor(JsonAccessor, collections.abc.MutableSequence):

        """ Store a list of ItemIDs """
        TYPE = ITEM_TYPES.LIST

        def getDefaultContent(self):
            return list()

        def __len__(self):
            return len(self.getContent())

        def __getitem__(self, key):
            return self.getItemSaver().getItem(self.getContent()[key])

        def __delitem__(self, key):
            self.getContent().__delitem__(key)
            self.touchContent()

        def __setitem__(self, key, value):
            self.getContent()[key] = value.getItemId()
            self.touchContent()

        def insert(self, key, value):
            self.getContent().insert(key, value.getItemId())
            self.touchContent()

        def childIds(self):
            return iter(self.getContent())

        def childIdsWithKeys(self):
            c = self.getContent()
            return zip(range(len(c)), c)

    @RegisteredAccessor
    class FileAccessor(BaseAccessor):

        """ Store bytes """
        TYPE = ITEM_TYPES.FILE

        def __init__(self, item):
            super().__init__(item)
            contentType = item.getContentType()
            rest = contentType[len(self.TYPE):]
            l = len(rest)
            if l == 0:
                self.mimeType = None
            else:
                assert rest[0] == '('
                assert rest[-1] == ')'
                self.mimeType = rest[1:-1]

        def saveFromPath(self, path):
            """ Save file at path into this item """
            with path.open('rb') as f:
                self.saveFromStream(f, io.DEFAULT_BUFFER_SIZE)

        def loadIntoPath(self, path):
            with path.open('wb') as f:
                for b in self.getContentIterator():
                    f.write(b)

        def childIds(self):
            return ()

        def childIdsWithKeys(self):
            return ()
