"""
    Test the sync Mixin

    Also implicitly tests the server that is synched against
"""

from ..shared.permissions import *
from ..shared import crypto
import math
import itertools
import io
import pathlib
import logging
import queue
import shutil
import tempfile
import unittest

from . import client
from . import sync

from .callbacks import TestCallbacks

from .net import AccessRestricted
from ..shared.conventions import ITEM_TYPES
from ..shared import utilcrypto

logger = logging.getLogger(__name__)

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test-" + __name__))

SERVER = "TestServer"


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))


class SyncClient(sync.SyncMixin, client.CatalogMixin, client.S5Client):
    pass


class TestSynchronizationMixIn(unittest.TestCase):

    """ Test the sync mixin against an S5Server """

    @classmethod
    def setUpClass(self):
        from s5.server.server import S5Server
        self.serverDir = TEMP_DIRECTORY / 'ServerDir'
        server = S5Server(self.serverDir)
        self.server = server
        server.initializeNew()
        self.exQ = queue.Queue()

        def eh(socket, addr, ex):
            #logging.getLogger("ServerTestErrorHandler").error("Exception %s",ex,exc_info = ex)
            self.exQ.put(ex)
        server.exceptionHandler = eh
        server.setup('', 0)  # localhost, OS-chosen Port
        self.address = server.getAddress()

        self.fingerprint = utilcrypto.getFingerprintFromAsymmetricKey(
            server.publicKey,
            TestCallbacks().getNewServerAsymmetricKeyFingerprintMethod())

        server.serveInThread()

        self.i = [1]

    @classmethod
    def tearDownClass(self):
        self.server.close()
        e = None
        while True:
            try:
                raise self.exQ.get(False) from e
            except queue.Empty:
                if e is not None:
                    raise e
                return
            except Exception as x:
                e = x

    def setUp(self):
        # Be Bob ################

        i = self.i[0]
        self.i[0] = i + 1

        i = "TestAgainstServer %02d" % i

        folder = TEMP_DIRECTORY / i / 'Bob'
        cb = TestCallbacks()
        cb.dataDir = folder
        cb.expectedFingerprint = self.fingerprint
        cb.symEncryption = "aes-128-cbc-pkcs7pad"
        cb.asymEncryption = "rsa-1024-oaep-sha1"  # Faster
        cb.versioningScheme = '1'
        cb.userEmail = 'Bob@test.net'
        bobClient = SyncClient(cb)
        bobClient.initializeNew()

        bobClient.addServer(SERVER, *self.address)

        t = self.server.createToken("cb.email")
        a = bobClient.sendTokenToServer(SERVER, t)
        assert a

        # Be Fred ##############

        folder = TEMP_DIRECTORY / i / 'Fred'
        cb = TestCallbacks()
        cb.dataDir = folder
        cb.asymEncryption = 'rsa-1024-oaep-sha1'
        cb.expectedFingerprint = self.fingerprint
        cb.symEncryption = "null"
        cb.userEmail = 'fred@test.net'

        fredClient = SyncClient(cb)
        fredClient.initializeNew()
        fredClient.addServer(SERVER, *self.address)

        # They use different Keys
        self.assertNotEqual(fredClient.getUserPublicKey(),
                            bobClient.getUserPublicKey())

        # create second client for bob with same key
        bobKey, bobKeyExportPW = bobClient.exportUserKey()

        folder = TEMP_DIRECTORY / i / 'Bob2'
        cb = TestCallbacks()
        cb.dataDir = folder
        cb.asymEncryption = 'rsa-1024-oaep-sha1'
        cb.expectedFingerprint = self.fingerprint
        cb.symEncryption = "null"
        cb.userEmail = 'Bob@test.net'

        bob2Client = SyncClient(cb)
        # make servers belive that this client is also bob:
        cb.importKeyPassword = bobKeyExportPW
        bob2Client.initializeWithExistingKey(bobKey)
        bob2Client.addServer(SERVER, *self.address)
        bob2Client.setRootId(bobClient.getRootItem().itemId)

        self.assertEqual(bob2Client.getUserPublicKey(),
                         bobClient.getUserPublicKey())

        self.fredClient = fredClient
        self.bobClient = bobClient
        self.bob2Client = bob2Client
        # Be Bob

        # build the following ItemTree:
        #   Bob's root
        #    └──d1
        #        ├──d1.1
        #        │   ├──i1.1.1
        #        │   └──i1.1.2
        #        ├──d1.2
        #        │   └──i1.2.1
        #        └──d1.3
        #            └──i1.3.1

        i = bobClient.newItem(ITEM_TYPES.JSON)
        i.setContent(["Bobs Secrets"])
        i.save()
        bobClient.putItemByPath(i, ['private', 'data'], create_parents=True)

        i = bobClient.newItem(ITEM_TYPES.JSON)
        i.setContent("i1.1.1")
        i.save()
        bobClient.putItemByPath(
            i, ['d1', 'd1.1', 'i1.1.1'], create_parents=True)

        i = bobClient.newItem(ITEM_TYPES.JSON)
        i.setContent("i1.1.2")
        i.save()
        bobClient.putItemByPath(
            i, ['d1', 'd1.1', 'i1.1.2'], create_parents=True)

        i = bobClient.newItem(ITEM_TYPES.JSON)
        i.setContent("i1.2.1")
        i.save()
        bobClient.putItemByPath(
            i, ['d1', 'd1.2', 'i1.2.1'], create_parents=True)

        i = bobClient.newItem(ITEM_TYPES.JSON)
        i.setContent("i1.3.1")
        i.save()
        bobClient.putItemByPath(
            i, ['d1', 'd1.3', 'i1.3.1'], create_parents=True)

    def test_twoClientsSameKeyNoShare(self):
        bobClient = self.bobClient
        bob2Client = self.bob2Client

        rootItem = bobClient.getRootItem()
        rootId = rootItem.itemId

        # synchronize root without share
        res = bobClient.synchronizeItemTreeToServer(
            rootItem, SERVER, addUnsynced=True)
        self.assertEqual(len(res.updated), 11)

        # sync again, all ignored
        res = bobClient.synchronizeItemTreeToServer(
            rootItem, SERVER, addUnsynced=True)
        self.assertEqual(len(res.ignored), 11)

        # get the Tree
        res = bob2Client.synchronizeItemIdsFromServer(
            [rootId], SERVER, True)

        l = bob2Client.iterateItemTree(bob2Client.getRootItem())
        l = list(l)
        self.assertEqual(len(l), 11)
        item = bob2Client.getItemByPath(['d1', 'd1.3', 'i1.3.1'])
        self.assertEqual(item.getContent(), "i1.3.1")

    def test_twoClientsSameKeyWithShare(self):
        bobClient = self.bobClient
        bob2Client = self.bob2Client

        rootItem = bobClient.getRootItem()
        rootId = rootItem.itemId

        # makes a new share, the owner is added
        shareId = bobClient.createShare(SERVER, "bobShares")

        # synchronizes all items to the server with the new share
        bobClient.shareItem(SERVER, shareId, rootItem, True)

        # get the Tree
        bob2Client.synchronizeItemIdsFromServer([rootId], SERVER, True)

        l = bob2Client.iterateItemTree(bob2Client.getRootItem())
        l = list(l)
        self.assertEqual(len(l), 11)
        item = bob2Client.getItemByPath(['d1', 'd1.3', 'i1.3.1'])
        self.assertEqual(item.getContent(), "i1.3.1")

    def test_twoClientsDifferentKeyWithShare(self):
        bobClient = self.bobClient
        fredClient = self.fredClient

        item = bobClient.getItemByPath(['d1'])
        itemId = item.itemId

        # makes a new share, the owner is added
        shareId = bobClient.createShare(SERVER, "SharedWFred", )

        bobClient.addUserToShare(
            SERVER,
            shareId,
            "TestFred",
            PermissionSet(
                WRITE_ITEMS,
                READ_ITEMS),
            fredClient.getUserPublicKey())

        # synchronizes items to the server with the new share
        bobClient.shareItem(SERVER, shareId, item, True)

        qShareIds = fredClient.queryShares(SERVER)
        self.assertIn(shareId, qShareIds)

        fredClient.putItemIdByPath(
            itemId, ['shared', 'fromBob'], create_parents=True)

        # get the Tree
        fredClient.synchronizeItemFromServer(
            fredClient.getRootItem(), SERVER, True)

        l = fredClient.iterateItemTree(fredClient.getRootItem())
        l = list(l)
        self.assertEqual(len(l), 10)
        item = fredClient.getItemByPath(
            ['shared', 'fromBob', 'd1.1', 'i1.1.2'])
        self.assertEqual(item.getContent(), "i1.1.2")

    def test_syncThenShareOther(self):
        fredClient = self.fredClient
        # give fred an account, so he can connect
        fredClient.sendTokenToServer(SERVER, self.server.createToken("fred"))
        bobClient = self.bobClient
        item = bobClient.getItemByPath(['d1', 'd1.1'])
        itemId = item.itemId

        # create a share for self,
        shareId = bobClient.createShare(SERVER, "SharedWithBob2")

        bobClient.shareItem(SERVER, shareId, item,
                            recursive=True)

        fredClient.putItemIdByPath(
            itemId, ['shared', 'fromBob'], create_parents=True)

        # can not get That item since it is not local:
        with self.assertRaises(KeyError):
            fredClient.getItemByPath(['shared', 'fromBob'])

        res = fredClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, True)
        self.assertEqual(res.forbidden, {itemId})

        bobClient.addUserToShare(
            SERVER,
            shareId,
            "TestFred",
            PermissionSet(
                WRITE_ITEMS,
                READ_ITEMS),
            fredClient.getUserPublicKey())

        res = fredClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, True)
        self.assertEqual(res.forbidden, set())

        item = fredClient.getItemByPath(['shared', 'fromBob', 'i1.1.1'])
        self.assertEqual('i1.1.1', item.getContent())

    def test_pullVersion(self):
        """ Push three Versions of an item to Server, Get them by id"""
        bobClient = self.bobClient
        item = bobClient.newItem(ITEM_TYPES.FILE)

        item.saveNewContent(b'V1')
        res1 = bobClient.synchronizeItemTreeToServer(
            item, SERVER, addUnsynced=True)

        item.saveNewContent(b'V2')
        res2 = bobClient.synchronizeItemTreeToServer(
            item, SERVER, addUnsynced=True)

        item.saveNewContent(b'V3')
        res3 = bobClient.synchronizeItemTreeToServer(
            item, SERVER, addUnsynced=True)

        v1 = list(res1.updated)[0][2]
        v2 = list(res2.updated)[0][2]
        v3 = list(res3.updated)[0][2]

        self.assertEqual(item.getContentBytes(), b'V3')

        bobClient.synchronizeItemIdFromServerWithVersion(
            item.itemId, v1, SERVER)
        self.assertEqual(item.getContentBytes(), b'V1')

        bobClient.synchronizeItemIdFromServerWithVersion(
            item.itemId, v3, SERVER)
        self.assertEqual(item.getContentBytes(), b'V3')

        bobClient.synchronizeItemIdFromServerWithVersion(
            item.itemId, v2, SERVER)
        self.assertEqual(item.getContentBytes(), b'V2')

        bobClient.synchronizeItemIdFromServerWithVersion(
            item.itemId, v2, SERVER)
        self.assertEqual(item.getContentBytes(), b'V2')

        bobClient.synchronizeItemFromServer(item, SERVER, False)
        self.assertEqual(item.getContentBytes(), b'V3')

    def test_replaceKeyInShare(self):
        bobClient = self.bobClient
        fredClient = self.fredClient
        # give fred an account, so he can connect
        fredClient.sendTokenToServer(SERVER, self.server.createToken("fred"))
        item = bobClient.getItemByPath(['d1'])
        itemId = item.itemId
        shareId = bobClient.createShare(SERVER, "testReplaceKey")
        bobClient.shareItem(SERVER, shareId, item, False)

        fact = crypto.getAsymmetricEncryptionAlgorithm('rsa-1024-oaep-sha1')
        tempKey = fact.generatePrivateKey()
        tempPub = fact.getPublicFromPrivate(tempKey)

        bobClient.addUserToShare(SERVER, shareId, "TestFred",
                                 PermissionSet(READ_ITEMS), tempPub)

        # item is shared with fred using another key
        # Fred can not access

        res = fredClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, False)
        self.assertEqual(res.forbidden, {itemId})

        fredClient.replaceKeyInShareMemberWithOwn(
            SERVER, shareId, tempKey)

        res = fredClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, False)
        self.assertEqual(res.forbidden, set())
        self.assertEqual(res.updated, {(itemId, None, 1)})

    def test_changePermissions(self):
        """ Test if changed permissions work """
        fredClient = self.fredClient
        # give fred an account, so he can connect
        fredClient.sendTokenToServer(SERVER, self.server.createToken("fred"))
        bobClient = self.bobClient
        item = bobClient.newItem(ITEM_TYPES.FILE)
        item.saveNewContent(b'plop')
        itemId = item.itemId

        shareId = bobClient.createShare(SERVER, "testChangePerms")

        bobClient.shareItem(SERVER, shareId, item, recursive=False)

        # fred no member -> forbidden
        res = fredClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, True)
        self.assertEqual(res.forbidden, set([itemId]))

        bobClient.addUserToShare(
            SERVER,
            shareId,
            "TestFred",
            PermissionSet(),
            fredClient.getUserPublicKey())

        # fred no Permission to Read -> forbidden
        res = fredClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, True)
        self.assertEqual(res.forbidden, set([itemId]))

        bobClient.changeShareMemberPermissions(
            SERVER,
            shareId,
            "TestFred",
            PermissionSet(READ_ITEMS))

        # fred allowed -> NOT forbidden
        res = fredClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, True)
        self.assertEqual(res.forbidden, set())

        self.assertEqual(fredClient.getItem(itemId).getContentBytes(), b'plop')

    def test_conflict(self):
        """ Client1 writes an item (1), pushes, writes again(2) but does not push
        again.
        Client2 pulls, writes(3), pushes.
        Client1 Pushes and gets a conflict
        Client1 pulls and gets a conflict
        Client 1 pulls, overwriting local changes, succeds
        client1 writes again (2)
        client1 pushes, succeeds
        client2 pulls
        client2 has content 2
        """

        bobClient = self.bobClient
        bob2Client = self.bob2Client

        item = bobClient.newItem(ITEM_TYPES.JSON)
        itemId = item.itemId

        item.setContent(1)
        item.save()
        res = bobClient.synchronizeItemTreeToServer(
            item, SERVER, addUnsynced=True)

        item.setContent(2)
        item.save()

        bob2Client.synchronizeItemIdsFromServer([itemId], SERVER, False)
        b2Item = bob2Client.getItem(itemId)
        self.assertEqual(b2Item.getContent(), 1)

        b2Item.setContent(3)
        b2Item.save()
        bob2Client.synchronizeItemTreeToServer(b2Item, SERVER)

        # Pushing gives a conflict (itemId, localVid, remoteVid)
        res = bobClient.synchronizeItemTreeToServer(item, SERVER)
        con = list(res.conflicts)[0]
        self.assertEqual(con[0], itemId)
        conflictVersionId = con[2]
        self.assertEqual(conflictVersionId, 2)

        # Pulling gives the same conflict
        res = bobClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, False)
        self.assertEqual(res.conflicts, {con})

        # Pull overwriting local conflicts:
        res = bobClient.synchronizeItemIdsFromServer(
            [itemId],
            SERVER,
            False,
            overwriteLocalChanges=True)
        # [itemId, localVid, remoteVid] is now updated instead of conflict
        self.assertEqual(res.updated, {con})
        self.assertEqual(item.getContent(), 3)  # Client2's changes

        # write the 2 again
        item.setContent(2)
        item.save()

        # sync it, works now
        bobClient.synchronizeItemTreeToServer(item, SERVER)

        # client2 pulls and has the 2
        bob2Client.synchronizeItemIdsFromServer([itemId], SERVER, False)
        self.assertEqual(b2Item.getContent(), 2)

    def test_inheritedShareConflictDetectons(self):
        """
            Item A is referenced by item1 and item2.
            item1 is shared with group1
            item2 is shared with group2
            Synchronizing with `addChildren` itemA shold inhreit the share
            group of its parents, but since there are 2 parents with different
            groups, an Exception must be raised.
        """

        bobClient = self.bobClient

        item = bobClient.newItem(ITEM_TYPES.JSON)
        item.setContent(1)
        item.save()

        bobClient.putItemByPath(
            item,
            ['testShareconflict', '1', 'item'],
            create_parents=True)

        bobClient.putItemByPath(
            item,
            ['testShareconflict', '2', 'item'],
            create_parents=True)

        sg1 = bobClient.createShare(SERVER, "shConflictTest1")
        sg2 = bobClient.createShare(SERVER, "shConflictTest2")

        bobClient.shareItem(
            SERVER,
            sg1,
            bobClient.getItemByPath(['testShareconflict', '1']),
            recursive=False)
        bobClient.shareItem(
            SERVER,
            sg2,
            bobClient.getItemByPath(['testShareconflict', '2']),
            recursive=False)

        with self.assertRaises(Exception):
            res = bobClient.synchronizeItemTreeToServer(
                bobClient.getItemByPath(['testShareconflict']),
                SERVER,
                addUnsynced=True)

    def test_addUserToShareFromOtherGroup(self):
        """
            Create a share group, add fred.
            Create anotherone, add fred using his email, other data from sg1.
        """
        bobClient = self.bobClient
        fredClient = self.fredClient
        item = bobClient.getItemByPath(['d1'])
        itemId = item.itemId

        sg1 = bobClient.createShare(SERVER, "testAddByOther1")

        bobClient.addUserToShare(
            SERVER,
            sg1,
            "TestFred",
            PermissionSet(),
            fredClient.getUserPublicKey())

        sg2 = bobClient.createShare(SERVER, "testAddByOther2")

        bobClient.addUserToShareFromOtherGroup(
            SERVER,
            sg2,
            "TestFred",
            PermissionSet(READ_ITEMS),
            sg1)

        bobClient.shareItem(SERVER, sg2, item, False)

        res = fredClient.synchronizeItemIdsFromServer(
            [itemId], SERVER, False)
        self.assertEqual(res.updated, {(itemId, None, 1)})

    def test_onlyAccountCanCreateGroup(self):
        bobClient = self.bobClient
        fredClient = self.fredClient

        with self.assertRaises(AccessRestricted):
            # fred is not member of a group, nor has an account
            # can do nothing except sending tokens.
            fredClient.pingServer(SERVER)

        sg1 = bobClient.createShare(SERVER, "testAddByOther1")

        bobClient.addUserToShare(
            SERVER,
            sg1,
            "TestFred",
            PermissionSet(),
            fredClient.getUserPublicKey())

        # now fred is a member of a group, he can do everything except creating
        # groups
        fredClient.pingServer(SERVER)

        # With an own account, fred can create a group
        token = self.server.createToken("Fred")
        fredClient.sendTokenToServer(SERVER, token)
        self.fredClient.createShare(SERVER, "FredsGroup?")
