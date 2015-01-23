import time
import pathlib
import logging
import shutil
import tempfile
import unittest

from . import client

from .callbacks import TestCallbacks

from . import filesync

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))


logger = logging.getLogger(__name__)


class FileSyncClient(
        filesync.FileSyncMixin,
        client.IterationMixin,
        client.S5Client):
    pass


class TestFsync(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        temp = TEMP_DIRECTORY / 'TestTool'
        s5dir = temp / 'client'

        cb = TestCallbacks()
        cb.dataDir = s5dir
        c = FileSyncClient(cb)
        c.initializeNew()

        d = temp / 'data'
        d.mkdir()
        (d / 'folder').mkdir()
        (d / 'folder' / 'subfolder').mkdir()

        with (d / 'folder' / 'file2').open('wt') as f:
            f.write('Content2')
        with (d / 'folder' / 'file1').open('wt') as f:
            f.write('Content')
        with (d / 'folder' / 'subfolder' / 'file1').open('wt') as f:
            f.write('Content')

        (d / 'otherfolder').mkdir()

        cls.d = d
        cls.t = temp
        cls.s5dir = s5dir

    def test_updateCatalog(self):
        cb = TestCallbacks()
        cb.dataDir = self.s5dir
        c = FileSyncClient(cb)

        ctlgPath = ('SyncFiles',)

        c.updateCatalogFromFileSystem(ctlgPath, self.d)

        # get item from expected Path
        item = c.getItemByPath(ctlgPath)
        self.assertEqual(item.getContentType(), 'urn:x-s5:map(urn:x-s5:file)')

        allPaths = []
        path = []

        def visit(key, down, up, **_):
            if key is None:
                key = 'root'
            if down:
                path.append(key)
            if down and up:
                allPaths.append(list(path))
            if up:
                path.pop()
        # should fill the item with children,grandchildren,... test all paths
        # to leaves
        c.walkItemTree(item, visit, ([], []))
        self.assertEqual(sorted(allPaths),
                         [["root", "folder", "file1"],
                          ["root", "folder", "file2"],
                          ["root", "folder", "subfolder", "file1"],
                          ["root", "otherfolder"]])

        # create a new File
        jpg = self.d / 'test.jpg'
        with jpg.open("wb") as f:
            f.write(b'')

        # should not be in Catalog
        with self.assertRaises(KeyError):
            item['test.jpg']

        # put it in Catalog
        with self.assertLogs(filesync.__name__, "DEBUG") as cm:
            c.updateCatalogFromFileSystem(ctlgPath, self.d,
                    update_existing=True)
        self.assertRegex(cm.output[0], ".*Item is new.*")
        self.assertRegex(cm.output[1], ".*Updating .* from File.*")
        self.assertEqual(len(cm.output), 2)

        # test if mimeType detection works
        self.assertEqual(item['test.jpg'].mimeType, 'image/jpeg')

        lm = item['test.jpg'].getLastModified()
        with jpg.open("wb") as f:
            f.write(b'')

        # LM in Catalog did not change
        self.assertEqual(lm, item['test.jpg'].getLastModified())

        with self.assertLogs(filesync.__name__, "DEBUG") as cm:
            c.updateCatalogFromFileSystem(ctlgPath, self.d,
                    update_existing=True)
        self.assertRegex(cm.output[0], ".*newer MTime.*same Content.*")
        self.assertEqual(len(cm.output), 1)

        # LM changed in Catalog
        self.assertLess(lm, item['test.jpg'].getLastModified())

        time.sleep(0.01)
        with jpg.open("wb") as f:
            f.write(b'Content')

        with self.assertLogs(filesync.__name__, "DEBUG") as cm:
            c.updateCatalogFromFileSystem(ctlgPath, self.d,
                    update_existing=True)
        self.assertRegex(cm.output[0], ".*newer MTime.*different Content.*")
        self.assertRegex(cm.output[1], ".*Updating .* from File.*")
        self.assertEqual(len(cm.output), 2)

        jpg.unlink()

        with self.assertLogs(filesync.__name__, "INFO") as cm:
            c.updateCatalogFromFileSystem(ctlgPath, self.d,
                    update_existing=True)
        self.assertRegex(cm.output[0], ".*deleted.*")
        self.assertEqual(len(cm.output), 1)

        # should not be in Catalog
        with self.assertRaises(KeyError):
            item['test.jpg']
