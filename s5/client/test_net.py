import unittest
from . import net


class TestClientProtocoll(unittest.TestCase):

    def test_attachedType(self):
        self.assertTrue(
            callable(net.ClientProtocol.getNewVersionsForItems.ItemsParam))
