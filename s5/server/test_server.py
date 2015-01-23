from ..shared import crypto
from ..shared import utilcrypto
from ..shared import permissions
from ..shared.permissions import *
import configparser
import pathlib
import threading
import shutil
import tempfile
import unittest

from . import server

from .server import AccessRestricted

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))

TEST_PUB_KEY_BOB = {'algorithm': 'bogus', 'type': 'public',
                    'modulus': 4267, 'public exponent': 3}
TEST_FPR_BOB = utilcrypto.getFingerprintFromAsymmetricKey(
    TEST_PUB_KEY_BOB, 'sha256')

TEST_PUB_KEY_FRED = {
    'algorithm': 'bogus',
    'type': 'public',
    'modulus': 5773,
    'public exponent': 3}
TEST_FPR_FRED = utilcrypto.getFingerprintFromAsymmetricKey(
    TEST_PUB_KEY_FRED, 'sha256')

assert TEST_PUB_KEY_BOB != TEST_PUB_KEY_FRED
assert TEST_FPR_BOB != TEST_FPR_FRED


class TestServerMessageHandler(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.d = TEMP_DIRECTORY / "db.sqlite"
        self.o = TEMP_DIRECTORY / 'Objects'
        db = server.ServerDataBase(self.d)
        db.createDatabase()
        db.upgradeDatabase(0)
        db.setSetting('userkey.fingerprintmethod', 'sha256')

        self.defaults = dict(
            encryptionMethod="aes-128-cbc-pkcs7pad",
            contentEncryptionIV=None,
            encryptedItemKey="123456",
            encryptedContentType="base64data",
            typeEncryptionIV=None,
            hashEncryptionIV=None,
            hashMethod="sha256",
            compressionMethod="bz2-9",
            shareId=None,
            itemKeyEncryptionIV=None
        )

        _, self.i1v1, _ = db.addItem(
            itemId="a",
            time=100,

            user=TEST_FPR_BOB,
            versioningScheme="last10",

            encryptedContentHash="012345ABCDEF",
            **self.defaults
        )
        db.activateVersion('a', self.i1v1, 0)

        _, self.i1v2, _ = db.addItemVersion(
            itemId="a",
            time=200,

            oldVersionId=self.i1v1,

            encryptedContentHash="012345ABCDEF",
            user=TEST_FPR_BOB,
            **self.defaults
        )
        db.activateVersion('a', self.i1v2, 0, self.i1v1)

        _, self.i1v3, _ = db.addItemVersion(
            itemId="a",
            time=300,

            oldVersionId=self.i1v2,

            encryptedContentHash="012345ABCDEF",
            user=TEST_FPR_BOB,

            **self.defaults
        )
        db.activateVersion('a', self.i1v3, 0, self.i1v2)

        _, self.i2v1, _ = db.addItem(
            itemId="b",
            time=400,

            encryptedContentHash="012345ABCDEF",
            user=TEST_FPR_BOB,
            versioningScheme="last10",

            **self.defaults
        )
        db.activateVersion('b', self.i2v1, 0)

        db.addToken("SECRETTOKEN", "TestBobAccount")
        db.mapUserByToken(TEST_FPR_BOB, "SECRETTOKEN")

    def test_addItemVersions(self):
        smh = server.ServerMessageHandler(
            self.d, self.o, 'TestClientAddr', 'ServerPubKey', "ServerPrivKey",
            None)

        smh.acceptClientByPublicKey(TEST_PUB_KEY_BOB)

        itemId = "0123456789ABCDEF0123456789ABCDEF"
        success, nv, offendingVid, unchanged = smh.addItemVersion(
            itemId=itemId,
            versioningScheme='last10',
            oldVersionId=None,
            encryptedContentHash="012345ABCDEF",
            **self.defaults)
        self.assertTrue(success)
        self.assertFalse(unchanged)

        success, offendingVid = smh.storeItemVersionData((b"",), itemId, nv)

        self.assertTrue(success)
        self.assertIsNone(offendingVid)

        ov = nv  # 1

        success, nv, offendingVid, unchanged = smh.addItemVersion(
            itemId=itemId,
            oldVersionId=ov,
            encryptedContentHash="012345ABCDEF",
            **self.defaults)
        self.assertTrue(success)
        self.assertIsNone(offendingVid)
        self.assertTrue(unchanged)  # new Version, same Content

        oov = ov  # 1
        ov = nv  # 2

        # above, contenthash was allways same, change that

        # try to add version with wrong oldVid
        success, nv, offendingVid, unchanged = smh.addItemVersion(
            itemId=itemId,
            oldVersionId=oov,
            encryptedContentHash="DifferentHash",
            **self.defaults)

        self.assertFalse(success)
        self.assertIsNone(nv)
        self.assertIsNone(unchanged)
        self.assertEqual(offendingVid, ov)

        # add new Version correctly, with differing Data
        success, nv, offendingVid, unchanged = smh.addItemVersion(
            itemId=itemId,
            oldVersionId=ov,
            encryptedContentHash="DifferentHash",
            **self.defaults)
        self.assertTrue(success)
        self.assertIsNone(offendingVid)
        self.assertFalse(unchanged)

        # Store Data with too old vid:
        success, offendingVid = smh.storeItemVersionData(
            (b"",), itemId, nv, oov)
        self.assertFalse(success)
        self.assertEqual(offendingVid, ov)

    def test_getNewItemVersions(self):
        smh = server.ServerMessageHandler(
            self.d, self.o, 'TestClient', "Server Public Key", "ServerPrivKey",
            None)
        smh.acceptClientByPublicKey(TEST_PUB_KEY_BOB)

        # we have old version of i1, current of i2
        v = smh.getNewItemVersions((("a", self.i1v1), ("b", self.i2v1)))
        v = list(v)
        # expect newest of i1, nothing of i2
        self.assertEqual(v, [("a", self.i1v3)])

        # we have old version of i1, current of i2
        v = smh.getNewItemVersions((("a", self.i1v2),))
        v = list(v)
        # expect newest of i1, nothing of i2
        self.assertEqual(v, [("a", self.i1v3)])

        # we have no version of i1 or i2
        v = smh.getNewItemVersions((("a", None), ("b", None)))
        v = list(v)
        # expect newest of i1, newest of i2
        self.assertEqual(v, [("a", self.i1v3), ("b", self.i2v1)])

        v = smh.getNewItemVersions((("-", 2),))
        v = list(v)
        self.assertEqual(v, [("-", "unknown")])

    def test_getItemVersionContent(self):
        itemId = "00000000000000000000000000000001"
        smh = server.ServerMessageHandler(
            self.d, self.o, 'TestClient', "Server Public Key", "ServerPrivKey",
            None)
        smh.acceptClientByPublicKey(TEST_PUB_KEY_BOB)
        success, nv, offendingVid, unchanged = smh.addItemVersion(
            itemId=itemId, versioningScheme='last10', encryptedContentHash="Item01Hash1", oldVersionId=None, **self.defaults)
        success, offendingVid = smh.storeItemVersionData((b"V1Content",),
                                                         itemId, nv)
        self.assertTrue(success)
        ov = nv
        success, nv, offendingVid, unchanged = smh.addItemVersion(
            itemId=itemId,
            oldVersionId=ov,
            encryptedContentHash="Item01Hash2",
            **self.defaults)
        self.assertTrue(success)
        success, offendingVid = smh.storeItemVersionData((b"V2Content",),
                                                         itemId, nv, ov)
        self.assertTrue(success)

        meta, contIter, size = smh.getItemVersion(itemId, ov)
        b = b''.join(contIter)

        self.assertEqual(size, len(b))
        self.assertEqual(b, b'V1Content')

        meta, contIter, size = smh.getItemVersion(itemId, nv)
        b = b''.join(contIter)

        self.assertEqual(size, len(b))
        self.assertEqual(b, b'V2Content')

    def test__ensurePermission(self):
        """ In a Share for Bob, with a Membership for Bob,
            Test that for a client authenticated as Bob,
            _ensurePermissionsInGroup works
        """
        smh = server.ServerMessageHandler(
            self.d, self.o, 'TestClient', "Server Public Key", "ServerPrivKey",
            None)
        smh.acceptClientByPublicKey(TEST_PUB_KEY_BOB)

        shareId = smh.createShare(
            "GroupEnsurePermissions", "encMeth", "macMeth", "FpMeth")

        smh.addShareMember(
            shareId=shareId,
            email="TestBob@example.com",
            permissions=PermissionSet(READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
            userPublicKey=TEST_PUB_KEY_BOB,
            shareKeyForUser="mock",
            auth="mock")

        smh._ensurePermissionsInGroup(shareId, permissions.READ_ITEMS)
        smh._ensurePermissionsInGroup(shareId, permissions.WRITE_ITEMS)
        smh._ensurePermissionsInGroup(shareId, permissions.READ_ITEMS,
                                      permissions.WRITE_ITEMS)

        with self.assertRaises(server.AccessRestricted):
            smh._ensurePermissionsInGroup(shareId, permissions.ADD_ITEMS)

        with self.assertRaises(server.AccessRestricted):
            smh._ensurePermissionsInGroup(shareId, permissions.READ_ITEMS,
                                          permissions.ADD_ITEMS)

        with self.assertRaises(server.AccessRestricted):
            smh._ensurePermissionsInGroup(shareId, permissions.WRITE_ITEMS,
                                          permissions.ADD_ITEMS)

        with self.assertRaises(server.AccessRestricted):
            smh._ensurePermissionsInGroup(
                shareId,
                permissions.WRITE_ITEMS,
                permissions.ADD_ITEMS,
                permissions.READ_ITEMS)

    def test_queryShares(self):
        """ As Bob, create a share with himself as Member and ensure that the
            id is in the results of queryShare
        """
        smh = server.ServerMessageHandler(
            self.d, self.o, 'TestClient', "Server Public Key", "ServerPrivKey",
            None)
        smh.acceptClientByPublicKey(TEST_PUB_KEY_BOB)
        shareId = smh.createShare(
            "GroupToQuery", "encMeth", "macMeth", "FpMeth")
        smh.addShareMember(
            shareId=shareId,
            email="TestBob@example.com",
            permissions=PermissionSet(READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
            userPublicKey=TEST_PUB_KEY_BOB,
            shareKeyForUser="mock",
            auth="mock")
        ids = smh.queryShares(name="UnknownGroup")
        self.assertEqual(list(ids), [])
        ids = smh.queryShares(name="GroupToQuery")
        self.assertIn(shareId, ids)
        ids = smh.queryShares()
        self.assertIn(shareId, ids)

    def test_PermissionsAddMember(self):
        """ Create a share as Bob, ensure Fred cant add a member """
        smh = server.ServerMessageHandler(
            self.d, self.o, 'TestClient', "ServerPublicKey", "PrivateKey", None)
        smh.acceptClientByPublicKey(TEST_PUB_KEY_BOB)

        shareId = smh.createShare(
            "GroupToTestAddMemberPerms", "encMeth", "macMeth", "FpMeth")

        # become Fred
        smh.acceptClientByPublicKey(TEST_PUB_KEY_FRED)

        with self.assertRaises(AccessRestricted):
            smh.addShareMember(
                shareId=shareId,
                email="TestBob@example.com",
                permissions=PermissionSet(
                    READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
                userPublicKey=TEST_PUB_KEY_BOB,
                shareKeyForUser="mock",
                auth="mock")

    def test_permissionsModifyMemberAsOwner(self):
        """ Create a group with a member as BOB,
            Bob can modify the Member, fred cant
        """
        smh = server.ServerMessageHandler(
            self.d, self.o, 'TestClient', "Server Public Key", "ServerPrivKey",
            None)
        smh.acceptClientByPublicKey(TEST_PUB_KEY_BOB)

        shareId = smh.createShare(
            "ShareNameTestPermsModMembOwner", "encMeth", "macMeth", "FpMeth")
        smh.addShareMember(
            shareId=shareId,
            email="TestFred@example.com",
            permissions=PermissionSet(READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
            userPublicKey=TEST_PUB_KEY_FRED,
            shareKeyForUser="mock",
            auth="mock")

        smh.updateShareMember(
            oldKey=TEST_PUB_KEY_FRED,
            shareId=shareId,
            email="TestFRED@example.ORG",  # <<--- the Change
            permissions=PermissionSet(READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
            userPublicKey=TEST_PUB_KEY_BOB,
            shareKeyForUser="mock",
            auth="mock")

        shareData, members = smh.getShare(shareId, False)

        assert len(members) == 1
        self.assertEqual(members[0]['email'], 'TestFRED@example.ORG')
        self.assertEqual(members[0]['userPublicKey']['type'], 'public')

    def test_permissionsModifyMemberAsMember(self):
        """ Create a group with a member as BOB,
            Fred can modify the Fred Member, but not the Bob Member
        """
        smh = server.ServerMessageHandler(
            self.d, self.o, 'TestClient', "Server Public Key", "ServerPrivKey",
            None)
        smh.acceptClientByPublicKey(TEST_PUB_KEY_BOB)

        shareId = smh.createShare(
            "TestPermsModMemberNonOwner", "encMeth", "macMeth", "FpMeth")

        smh.addShareMember(
            shareId=shareId,
            email="TestBob@example.com",
            permissions=PermissionSet(READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
            userPublicKey=TEST_PUB_KEY_BOB,
            shareKeyForUser="mock",
            auth="mock")

        smh.addShareMember(
            shareId=shareId,
            email="TestFred@example.com",
            permissions=PermissionSet(READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
            userPublicKey=TEST_PUB_KEY_FRED,
            shareKeyForUser="mock",
            auth="mock")

        # become Fred
        smh.acceptClientByPublicKey(TEST_PUB_KEY_FRED)

        # Can update own Record
        smh.updateShareMember(
            oldKey=TEST_PUB_KEY_FRED,
            shareId=shareId,
            email="TestFRED@example.ORG",  # <<--- the Change
            permissions=PermissionSet(READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
            userPublicKey=TEST_PUB_KEY_FRED,
            shareKeyForUser="mock",
            auth="mock")

        # Can Not Increase Own Privileges
        with self.assertRaises(AccessRestricted):
            smh.updateShareMember(
                oldKey=TEST_PUB_KEY_FRED,
                shareId=shareId,
                email="TestFRED@example.ORG",
                permissions=PermissionSet(READ_ITEMS, WRITE_ITEMS,
                                          LIST_MEMBERS, ADD_ITEMS),  # <--- Additional Privilege
                userPublicKey=TEST_PUB_KEY_FRED,
                shareKeyForUser="mock",
                auth="mock")

        # Can Not modify Bobs email
        with self.assertRaises(AccessRestricted):
            smh.updateShareMember(
                oldKey=TEST_PUB_KEY_BOB,
                shareId=shareId,
                email="TestBOB@example.ORG",
                permissions=PermissionSet(
                    READ_ITEMS, WRITE_ITEMS, LIST_MEMBERS),
                userPublicKey=TEST_PUB_KEY_BOB,
                shareKeyForUser="mock",
                auth="mock")

        shareData, members = smh.getShare(shareId, True)
        self.assertEqual(members[0]['email'], 'TestFRED@example.ORG')

        smh.close()

    def test_db(self):
        db = server.ServerDataBase(self.d)

        success, i3v1, offendingVid = db.addItem(
            itemId="c",
            time=100,

            user="Bob",
            versioningScheme="last10",

            encryptedContentHash="Item3V1Hash",
            **self.defaults
        )
        self.assertTrue(success)
        self.assertIsNone(offendingVid)
        self.assertIsNotNone(i3v1)

        success, offendingVid = db.activateVersion('c', i3v1, 0)

        self.assertTrue(success)

        success, i3v2, offendingVid = db.addItemVersion(
            itemId="c",
            time=200,

            oldVersionId=i3v1,

            encryptedContentHash="Item3V2Hash",
            user="Bob",
            **self.defaults
        )
        self.assertTrue(success)
        self.assertIsNone(offendingVid)

        success, offendingVid = db.activateVersion('c', i3v2, 0, i3v1)
        self.assertTrue(success, offendingVid)

        with self.assertRaises(Exception):
            self.deleteInactiveItemVersion("c", i3v2)


class TestS5Server(unittest.TestCase):

    def test_init(self):
        serverdir = TEMP_DIRECTORY / "TestServerInit"
        s = server.S5Server(serverdir)
        s.initializeNew()
        pubKey = s.publicKey

        self.assertEqual(pubKey['type'], 'public')
        del s

        s = server.S5Server(serverdir)

        with self.assertRaises(Exception):
            s.initializeNew()
        with self.assertRaises(Exception):
            s.upgrade()

        self.assertEqual(s.publicKey, pubKey)

    def test_setup(self):
        s = server.S5Server(TEMP_DIRECTORY / "ServerSetup")
        s.initializeNew()

        s.setup('', 0)
        addr, port = s.getAddress()
        self.assertGreater(port, 1024)

        s.close()
