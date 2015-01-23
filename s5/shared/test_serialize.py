import re
import unittest

from .serialize import *


class SerializeTest(unittest.TestCase):

    def test_serializeStr(self):
        self.assertEqual(strToBytes("Test"), b'Test')
        self.assertEqual(strToBytes("ü"), b'\xc3\xbc')

    def test_deserializeStr(self):
        self.assertEqual(bytesToStr(b'Test'), "Test")
        self.assertEqual(bytesToStr(b'\xc3\xbc'), "ü")

    def test_serializeObj(self):
        o = [1, 2, 3, 4, "ü"]
        b = objToBytes(o)
        self.assertEqual(b'[1, 2, 3, 4, "\u00fc"]', b)

    def test_deserializeObj(self):
        o = bytesToObj(b'[1,2,3]')
        self.assertEqual(o[1], 2)

    def test_coupled(self):
        s = ["ABCDE!@#$%^&äüöß", 1]
        self.assertEqual(bytesToObj(objToBytes(s)), s)

    def test_B64(self):
        b = bytes(range(0, 256))
        s = base64encode(b)
        self.assertRegex(s, "^[A-Za-z0-9+=/]+$")
        b2 = base64decode(s)
        self.assertEqual(b2, b)
