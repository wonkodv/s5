from unittest.mock import Mock
from ..shared import crypto
import io
import logging
import queue
import shutil
import unittest
import unittest.mock
import pathlib
import tempfile

from s5.server.server import S5Server

from . import client
from . import items

from .callbacks import TestCallbacks

from ..shared.conventions import ITEM_TYPES

logger = logging.getLogger(__name__)

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))


class TestReloadClient(unittest.TestCase):

    def test_storeLoad(self):
        dir = TEMP_DIRECTORY / "reloadClient"
        cb = TestCallbacks()
        cb.dataDir = dir
        c = client.S5Client(cb)
        c.initializeNew()
        itm = c.newItem('urn:x-s5:file(text/plain)')

        itm.saveNewContent('Test S5 Item'.encode('UTF-8'))

        itemId = itm.itemId

        del itm
        del c

        c = client.S5Client(cb)

        itm = c.getItem(itemId)

        self.assertEqual(itm.getContentBytes().decode('utf-8'), "Test S5 Item")


class TestS5Client(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.c = TEMP_DIRECTORY / "clientDir"
        assert not cls.c.exists()
        cb = TestCallbacks()
        cb.dataDir = cls.c
        c = client.S5Client(cb)
        c.initializeNew()

    def test_initUserKey(self):
        cb = TestCallbacks()
        cb.dataDir = TEMP_DIRECTORY / 'UserKeyTest'
        c = client.S5Client(cb)
        c.initializeNew()
        c._generateAndStoreUserKey()
        c.userKey = None
        k = c._getUserPrivateKey()
        self.assertEqual(k['type'], 'private')

    def test_newItem(self):
        cb = TestCallbacks()
        cb.dataDir = self.c
        c = client.S5Client(cb)

        itm = c.newItem('urn:x-s5:file(text/plain)')

        itm.saveNewContent('Test S5 Item'.encode('UTF-8'))

        itemId = itm.itemId

        i2 = c.getItem(itemId)
        b = i2.getContentBytes()
        s = b.decode("UTF-8")
        self.assertEqual(s, "Test S5 Item")

    def test_newItemNotSaved(self):
        d = TEMP_DIRECTORY / 'NotSavedTest'
        cb = TestCallbacks()
        cb.dataDir = d
        c = client.S5Client(cb)

        c.initializeNew()
        itm = c.newItem(ITEM_TYPES.FILE)
        itemId = itm.itemId

        del c
        del itm

        c = client.S5Client(cb)
        itm = c.getItem(itemId)

        itm.saveNewContent(b'Test Data')

        del c
        del itm

        c = client.S5Client(cb)
        itm = c.getItem(itemId)

        self.assertEqual(b'Test Data', itm.getContentBytes())

    def test_itemNotExisting(self):
        cb = TestCallbacks()
        cb.dataDir = self.c
        c = client.S5Client(cb)
        with self.assertRaises(KeyError):
            itm = c.getItem('35')

    def test_itemWeakRef(self):
        cb = TestCallbacks()
        cb.dataDir = self.c
        c = client.S5Client(cb)
        itm = c.newItem('urn:x-s5:file:text/plain')

        itm.saveNewContent('Test S5 Item'.encode('UTF-8'))

        itemId = itm.itemId
        itemObjectId = id(itm)

        itm2 = c.getItem(itemId)
        self.assertEqual(id(itm2), itemObjectId)

        del itm
        del itm2
        # GarbageCollection should remove the item

        itm = c.getItem(itemId)

        self.assertNotEqual(id(itm), itemObjectId)


class TestCatalogMixin(unittest.TestCase):

    class CatalogClient(client.CatalogMixin, client.S5Client):
        pass

    def test_itemByName(self):
        tmp = TEMP_DIRECTORY / 'TestCatalog'
        cb = TestCallbacks()
        cb.dataDir = tmp
        client = self.CatalogClient(cb)
        client.initializeNew()
        i = client.newItem(ITEM_TYPES.JSON)
        i.setContent([5])
        i.save()
        client.putItemByPath(i, ['JSON1'])

        with self.assertRaises(KeyError):
            client.getItemByPath(['unkown name'])

        i = client.newItem(ITEM_TYPES.JSON)
        i.setContent([1, 2, 3])
        i.save()

        with self.assertRaises(KeyError):
            # can not create parents without flag
            client.putItemByPath(i, ['level1', 'level2', 'level3'])

        client.putItemByPath(
            i, ['level1', 'level2', 'level3'], create_parents=True)

        i = client.newItem(ITEM_TYPES.JSON)
        i.setContent([5])
        i.save()

        with self.assertRaises(ValueError):
            # can not overwrite without Flag
            client.putItemByPath(i, ['level1', 'level2', 'level3'])

        client.putItemByPath(
            i, ['level1', 'level2', 'level3'], overwrite_existing=True)

        del client
        del i

        cb = TestCallbacks()
        cb.dataDir = tmp
        client = self.CatalogClient(cb)

        i = client.getItemByPath(['level1'])

        self.assertEqual(i.getContentType(), ITEM_TYPES.MAP)

        i = i['level2']['level3']

        self.assertEqual(i.getContentType(), ITEM_TYPES.JSON)
        self.assertEqual(i.getContent()[0], 5)

class TestIterationMixin(unittest.TestCase):

    class IterateCatalogClient(client.IterationMixin, client.CatalogMixin,
                               client.S5Client):
        pass

    def test_walkItemTree(self):
        cb = TestCallbacks()
        cb.dataDir = TEMP_DIRECTORY / 'TestTreeToWalk'
        c = self.IterateCatalogClient(cb)
        c.initializeNew()

        i = c.newItem(ITEM_TYPES.JSON)
        i.setContent([1, 2, 3])
        i.save()
        c.putItemByPath(i, ['d1', 'd1.1', 'f1.1.1'], create_parents=True)
        c.putItemByPath(i, ['d1', 'd1.2', 'f1.2.1'], create_parents=True)
        c.putItemByPath(i, ['d1', 'd1.2', 'f1.2.2'], create_parents=True)
        c.putItemByPath(i, ['d2', 'f2.1'], create_parents=True)
        c.putItemByPath(c.getRootItem(), ['d1', 'd1.1', 'rootLoop'])

        allPaths = []
        path = []

        def visit(key, down, up, **_):
            if key is None:
                key = 'root'
            if down:
                path.append(key)
            if down and up:
                # append leafes
                allPaths.append(list(path))
            if up:
                path.pop()
            return True

        def handleLoop(key, **_):
            allPaths.append(path + [key, "LOOOP"])
            return False

        c.walkItemTree(c.getRootItem(), visit, handleLoop)

        self.assertEqual(sorted(allPaths),
                         [['root', 'd1', 'd1.1', 'f1.1.1'],
                          ['root', 'd1', 'd1.1', 'rootLoop', 'LOOOP'],
                          ['root', 'd1', 'd1.2', 'f1.2.1'],
                          ['root', 'd1', 'd1.2', 'f1.2.2'],
                          ['root', 'd2', 'f2.1']])

    def test_iterateItemTree(self):
        """ Test if iterateItemTree iterates, and all ids onbly once """
        cb = TestCallbacks()
        cb.dataDir = (TEMP_DIRECTORY / 'TestTreeToIterateOver')
        c = self.IterateCatalogClient(cb)
        c.initializeNew()
        i = c.newItem(ITEM_TYPES.JSON)
        i.setContent([1, 2, 3])
        i.save()
        c.putItemByPath(i, ['d1', 'd1.1', 'f1.1.1'], create_parents=True)
        c.putItemByPath(i, ['d1', 'd1.2', 'f1.2.1'], create_parents=True)
        c.putItemByPath(i, ['d1', 'd1.2', 'f1.2.2'], create_parents=True)
        c.putItemByPath(i, ['d2', 'f2.1'], create_parents=True)
        r = c.getRootItem()
        c.putItemByPath(r, ['d1', 'd1.1', 'rootLoop'])
        it = c.iterateItemTree(r)

        self.assertEqual(next(it), r.itemId)

        self.assertIn(next(it), [r['d1'].itemId, r['d2'].itemId])
        l = list(it)
        self.assertEqual(len(l), 7)  # d2 d1.1 d1.2 f1.1.1 f1.2.1 f1.2.2 f2.1
