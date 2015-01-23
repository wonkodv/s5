import shutil
import pathlib
import tempfile
import unittest

from . import util

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))


class TestUtils(unittest.TestCase):

    def test_groupwiseIterator(self):
        l = list(map(list, util.groupwiseIterator(range(5), 2)))
        self.assertEqual(l, [[0, 1], [2, 3], [4]])

        l = list(map(list, util.groupwiseIterator(range(4), 2)))
        self.assertEqual(l, [[0, 1], [2, 3]])

        l = list(map(list, util.groupwiseIterator(range(4), 4)))
        self.assertEqual(l, [[0, 1, 2, 3]])

        l = list(map(list, util.groupwiseIterator(range(11), 7)))
        self.assertEqual(l, [[0, 1, 2, 3, 4, 5, 6], [7, 8, 9, 10]])

    def testDatabase(self):
        db = util.CommonDatabase(TEMP_DIRECTORY / 'db')

        db.__enter__()
        db.__exit__(None, None, None)

        c = db.cursor()

        c.execute(" CREATE TABLE plop (id INT);")
        c.execute(" insert into plop values (1);")
        db.commit()

        with self.assertRaises(StopIteration):  # catch a sentinel
            with db:
                c.execute(" insert into plop values (2);")
                c.execute("select id from plop")
                x = c.fetchall()
                x = set(map(lambda row: row['id'], x))
                self.assertEqual(x, {1, 2})
                raise StopIteration()  # raise a sentinel

        # test that transaction was unrilled
        c.execute("select id from plop")
        x = c.fetchall()
        x = set(map(lambda row: row['id'], x))
        self.assertEqual(x, {1})

        db.close()
        with self.assertRaises(Exception):
            c.execute("SELECT 1")

    @util.addAttribute("x", 42)
    def test_addAttribute(self):
        self.assertEqual(self.test_addAttribute.x, 42)

    def test_fileSizeFormat(self):
        self.assertEqual(util.fileSizeFormat(5 * 1024), '5KB')
        self.assertEqual(util.fileSizeFormat(5.01 * 1024 * 1024), '5MB')

        self.assertEqual(util.fileSizeFormat(1 * 1024 * 1024), '1024KB')
        self.assertEqual(util.fileSizeFormat(3 * 1024 * 1024), '3MB')
