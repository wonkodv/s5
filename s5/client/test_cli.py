import os
import pathlib
from ..shared.conventions import ITEM_TYPES
from unittest.mock import Mock
import socket
import sys
import io
import shutil
import tempfile
import unittest

from .callbacks import TestCallbacks
from . import cli
from . import client

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))


class TestCliMixin(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.c = TEMP_DIRECTORY / "clientDir"
        assert not cls.c.exists()
        cb = TestCallbacks()
        cb.dataDir = cls.c
        t = cli.CliClient(cb)
        t.initializeNew()

        def makeItem(content, *path):
            i = t.newItem(ITEM_TYPES.FILE)
            t.putItemByPath(
                i, path, create_parents=True, overwrite_existing=True)
            i.saveNewContent(content)

        makeItem(b'Test data', 'test', 'data')
        makeItem(b'Lorem Ipsum', 'test', 'Text')
        makeItem(b'["This is a JSON File","not Json Item"]', 'test.json')
        makeItem(b'', 'd1', 'f1.1')
        makeItem(b'x', 'd1', 'd1.1', 'f1.1.1')
        makeItem(b'', 'd1', 'd1.1', 'f1.1.2')
        makeItem(b'', 'd1', 'd1.2', 'f1.2.1')
        makeItem(b'', 'd2', 'd2.1', 'f1.1.2')

    def setUp(self):
        cb = TestCallbacks()
        cb.dataDir = self.c
        t = cli.CliClient(cb)

        self.cliClient = t

    def test_new(self):
        m = Mock()
        m.read.return_value = b''
        self.cliClient.inStream = m
        self.cliClient.addItemToPath('test/new', m)
        with self.assertRaises(ValueError):
            self.cliClient.addItemToPath('test/new', m)

    def test_tree(self):
        t = self.cliClient
        i = t.getRootItem()
        out = io.BytesIO()
        self.cliClient.outStream = out
        t.printItemTree(
            'root', i, True, True, True, True, True, True, True, True)
        s = out.getvalue().decode('UTF-8')
        self.assertGreater(len(s), 500)

    def test_hex(self):
        t = self.cliClient
        i = t.getItemByPath(['test', 'data'])
        out = io.BytesIO()
        self.cliClient.outStream = out
        t.hexDumpItemContents(i, 10)

    def test_getItemBySpec(self):
        c = self.cliClient
        item = c.getItemBySpec('d1/d1.1/f1.1.1')
        itemId = item.itemId
        self.assertEqual(b'x', item.getContentBytes())

        del item

        item = c.getItemBySpec(itemId)
        self.assertEqual(b'x', item.getContentBytes())

        del item

        item = c.getItemBySpec(itemId[:5])
        self.assertEqual(b'x', item.getContentBytes())


    def test_garbageCollect(self):
        client = self.cliClient
        item = client.newItem(ITEM_TYPES.JSON)
        item.setContent([5])
        item.save()
        client.putItemByPath(
            item,
            ['level1', 'level2', 'level3'],
            create_parents=True)

        itemId = item.itemId

        client.removeUnreachableItems()

        # not deleted yet
        client.getItem(itemId)


        client.putItemIdByPath(
            "00000000000000000000000000000005",
            ['level1', "level2"],
            overwrite_existing=True)


        client.removeUnreachableItems()
        with self.assertRaises(KeyError, msg=itemId+" not deleted"):
            client.getItem(itemId)


class TestCli(unittest.TestCase):

    def test_cmd(self):
        cd = TEMP_DIRECTORY / 'cmd'

        cb = TestCallbacks()
        cb.dataDir = cd
        c = cli.CliClient(cb)
        c.initializeNew()

        del c

        cb = TestCallbacks()
        cb.dataDir = cd
        c = cli.CliClient(cb)

        i = c.newItem(ITEM_TYPES.JSON)
        i.setContent([1, 2, 3])
        i.save()
        c.putItemByPath(i, ['test', 'item'], create_parents=True)

        del i
        del c

        os.environ['S5_PASSWORD'] = TestCallbacks.password
        o = cli.parseArgs(
            '--data', str(cd), '--batch', 'item', 'dump', 'test/item')
        b = io.BytesIO()
        cli.main(o, outStream=b)
        self.assertEqual(b.getvalue(), b'[1, 2, 3]')

        o = cli.parseArgs(
            '--data',
            str(cd),
            '--batch',
            'item',
            'write',
            '--parents',
            'test2/item2')
        b = io.BytesIO()
        b.write(b'TestString')
        b.seek(0)
        i = cli.main(o, inStream=b)
        self.assertEqual(i,0)

        cb = TestCallbacks()
        cb.dataDir = cd
        c = cli.CliClient(cb)

        i = c.getItemByPath(['test2', 'item2'])
        self.assertEqual(i.getContentBytes(), b'TestString')
