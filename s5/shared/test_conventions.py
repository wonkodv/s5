import unittest

from .conventions import *


class TestConventions(unittest.TestCase):

    def test_isItemId(self):
        self.assertTrue(isItemId('0123456789ABCDEF0123456789ABCDEF'))
        self.assertFalse(isItemId('0123456789ABCDEF0123456789abcdef'))
        self.assertFalse(isItemId('0123456789ABCDEF0123456789ABCDE'))
        self.assertFalse(isItemId('0123456789ABCDEF0123456789ABCDE+'))
        self.assertFalse(isItemId('0123456789ABCDEF0123456789ABCDE '))
