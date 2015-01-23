import unittest
from .permissions import *


class TestPermissionSet(unittest.TestCase):

    def test_fromMask(self):
        s = PermissionSet.fromMask(10)
        s = set(s)
        self.assertEqual({WRITE_ITEMS, LIST_MEMBERS}, s)

    def test_toMask(self):
        s = PermissionSet(READ_ITEMS, ADD_ITEMS)
        m = s.toMask()
        self.assertEqual(m, 5)

    def test_hasAll(self):
        s = PermissionSet(READ_ITEMS, ADD_ITEMS, WRITE_ITEMS)
        self.assertTrue(s.hasAll(WRITE_ITEMS, READ_ITEMS))
        self.assertFalse(s.hasAll(WRITE_ITEMS, LIST_MEMBERS))
        with self.assertRaises(AssertionError):
            s.hasAll("Test")

    def test_in(self):
        s = PermissionSet(READ_ITEMS, ADD_ITEMS, WRITE_ITEMS)

        self.assertTrue(ADD_ITEMS in s)
        self.assertFalse(LIST_MEMBERS in s)

    def test_strInit(self):
        s = PermissionSet('READ_ITEMS', 'ADD_ITEMS', 'WRITE_ITEMS')
        self.assertEqual(set(s), {READ_ITEMS, ADD_ITEMS, WRITE_ITEMS})

    def test_toStr(self):
        s = PermissionSet('READ_ITEMS', 'ADD_ITEMS', 'WRITE_ITEMS')
        self.assertEqual(str(s), "[ADD_ITEMS, READ_ITEMS, WRITE_ITEMS]")

    def test_all(self):
        self.assertEqual(set(PermissionSet.ALL),
                         {REMOVE_ITEMS,
                          READ_ITEMS,
                          ADD_ITEMS,
                          WRITE_ITEMS,
                          LIST_MEMBERS})
