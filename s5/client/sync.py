"""
    Implements the SyncMixin, which adds all synchronization and sharing
    functionallity.

"""

import collections
import datetime
import logging
import socket

from . import client
from . import net


from .net import AccessRestricted

from ..shared import crypto
from ..shared import messaging
from ..shared import conventions
from ..shared import util
from ..shared import utilcrypto
from ..shared.permissions import *

logger = logging.getLogger(__name__)


class SyncMixin(client.IterationMixin):

    """ Does the Synchronization """

    def _do_upgrade(self, fromVersion):
        super()._do_upgrade(fromVersion)

        if fromVersion < 1:
            c = self.db.cursor()
            try:
                with self.db:
                    c.executescript("""
                        CREATE TABLE server (
                            name STRING PRIMARY KEY,
                            host STRING NOT NULL,
                            port INT NOT NULL,

                            fingerprint STRING NOT NULL,
                            fingerprintMethod STRING NOT NULL
                        );
                        CREATE TABLE sync(
                            server STRING NOT NULL,
                            itemId STRING NOT NULL,
                            shareId STRING,
                            versionId INT NOT NULL,
                            encryptedContentHash STRING NOT NULL,
                            direction STRING NOT NULL,
                            time TIMESTAMP NOT NULL,
                            PRIMARY KEY(server,itemId)
                            );""")
            finally:
                c.close()

    def _openClientProtocol(self, server):
        row = self.db_getServer(server)
        addr = row['host'], row['port']
        cs = socket.create_connection(
            addr, self.callbacks.getConnectionTimeout())
        cp = net.ClientProtocol(cs)

        def verifyServerKey(sk):
            fp = utilcrypto.getFingerprintFromAsymmetricKey(
                sk, row['fingerprintMethod'])
            if fp != row['fingerprint']:
                raise ValueError(
                    "Server Key Mismatch: %s != %s", fp, row['fingerprint'])
            return True
        cp.setup(
            self.getUserPublicKey(),
            self._getUserPrivateKey(),
            verifyServerKey,
            self.callbacks.getConnectionCipherSuites())
        return cp

    def sendTokenToServer(self, server, token):
        cp = self._openClientProtocol(server)
        try:
            return cp.sendToken(token)
        finally:
            cp.close()

    def synchronizeItemFromServer(self, item, server, depth):
        try:
            itemId = item.getItemId()
        except AttributeError:
            itemId = item
        return self.synchronizeItemIdsFromServer([itemId], server, depth)

    PullResult = collections.namedtuple(
        "PullResult", [
            "conflicts", "updated", "unknown", "ignored", "forbidden"])

    def synchronizeItemIdFromServerWithVersion(
            self,
            itemId,
            versionId,
            server):
        """
            Get a specific Version of an Item from the server
        """
        self._selfCheck()
        assert isinstance(versionId, int)
        assert conventions.isItemId(itemId)
        cp = self._openClientProtocol(server)
        try:
            result = self.PullResult(set(), set(), set(), set(), set())

            syncInfo = self.db_getSyncs([itemId], server)
            syncInfo = list(syncInfo)

            if len(syncInfo) == 0:
                syncInfo = None
            else:
                assert len(syncInfo) == 1
                syncInfo = syncInfo[0]

            itu = itemId, syncInfo, versionId
            itu = [itu]
            upd, forb = self._updateItemsToVersionFromServer(itu, server, cp)
            if forb:
                raise AccessRestricted("Access Forbidden to", *forb)

        finally:
            cp.close()

    def synchronizeItemIdsFromServer(self, itemIds, server, depth,
                                     overwriteLocalChanges=False):
        """
            For all ids, update item to newest version from server.
            If depth > 0, redo for all children, up to depth levels (True fo all).
            If recursive, items in `ids` that have an ancestor in `ids`
            the entire subtree will be synchronized twice.

            if an item was changed locally since the last sync or never synced
            but exists on the server, this item is not updated and put in
            conflicts (itemId, versionId).

            if item is newer on server and locally not changed since last update,
            the content and metadata is set to the servers version
            and put in updated (itemId, versionId).
            with `overwriteLocalChanges` set, local changes are ignored. will
            be reported as updated.

            If the item has the newest version, its id and vid is put in ignored.

            If an item is not on the server that id is put in unknown

            returns a PullResult"""

        self._selfCheck()
        cp = self._openClientProtocol(server)
        try:
            result = self.PullResult(set(), set(), set(), set(), set())

            if depth is False:
                depth = 0
            elif depth is True:
                pass
            else:
                depth = int(depth)

            def sync(idsToSync, path):
                # get an Iterator with info about local and Server Version
                nvfs = self._getNewestVersionFromServerForItems(
                    cp,
                    server,
                    idsToSync,
                    result)

                # filter items in conflict, unknown to the server or those up to date,
                # populate lists with those
                itu = self._filterConflicts(
                    nvfs, overwriteLocalChanges, result)

                # Get the update from the Server
                upd, forb = self._updateItemsToVersionFromServer(
                    itu, server, cp)

                result.updated.update(upd)  # addAll
                result.forbidden.update(forb)  # addAll

                # not using walkItemTree because that can not deal with children
                # appearing while an item is visited

                if depth is True or depth > len(path):
                    for itemId in idsToSync:
                        if not itemId in path:  # Loop Detection
                            try:
                                item = self.getItem(itemId)
                            except KeyError:
                                pass  # unknown or forbidden
                            else:
                                c = list(item.childIds())
                                sync(c, path + (itemId,))
            ids = list(itemIds)
            sync(ids, ())

            logger.info(
                "Synchronized From Server %s; ItemIds: %r, "
                "depth: %r, results: %r",
                server,
                itemIds,
                depth,
                result)

            return result
        finally:
            cp.close()

    def _getNewestVersionFromServerForItems(self, cp, server, ids, result):
        """ Ask the Server for the newes Version of each item """
        # Work on max 100 items at a time
        for group in util.groupwiseIterator(ids, 100):
            group = tuple(group)
            syncInfo = self.db_getSyncs(group, server)

            # put info from DB in index
            infoById = {}
            for s in syncInfo:
                infoById[s['itemId']] = s

            # getVersions wants a list of elements with type T
            T = cp.getNewVersionsForItems.ItemsParam

            # make a list of (ItemId,lastSyncVid) tuples
            versions = []
            for itemId in group:
                info = infoById.get(itemId, None)
                if info is not None:
                    v = info['versionId']
                else:
                    v = None
                versions.append(T(ItemId=itemId, VersionId=v))

            # get newer versions from server
            versionsFromServer = cp.getNewVersionsForItems(versions)

            # make set from which ids are remove that have newer versions on
            # server
            group = set(group)

            # yield ServerVersion with lastSyncInfo
            for serverVersionData in versionsFromServer:
                itemId = serverVersionData.ItemId
                versionId = serverVersionData.VersionId
                if versionId == 'unknown' or versionId is None:
                    result.unknown.add(itemId)
                elif versionId == 'unauthorized':
                    result.forbidden.add(itemId)
                else:
                    lastSyncData = infoById.get(itemId, None)
                    group.remove(itemId)
                    yield itemId, lastSyncData, versionId

            for itemId in group:
                lastSyncData = infoById.get(itemId, None)
                if lastSyncData is None:
                    result.ignored.add((itemId, None))
                else:
                    result.ignored.add((itemId, lastSyncData['versionId']))

    def _filterConflicts(self, nvfs, overwriteLocalChanges, result):
        """ Filter out items with conflicts, unknown to the server or already
            up to date, yield the ones that need updating.
        """
        for itemId, lastSync, serverVersionId in nvfs:
            if lastSync is None:
                localVersionId = None
            else:
                localVersionId = lastSync['versionId']

            if overwriteLocalChanges:
                conflict = False
            else:
                conflict = True
                if lastSync is None:
                    localVersionId = None
                    try:
                        self.getItem(itemId)
                        # Server sent Version, item was never synced, conflict
                    except KeyError:
                        # Item is on server and not on client -> no conflict
                        conflict = False
                else:
                    # item was synced before, test if it changed since
                    item = self.getItem(itemId)
                    currentItemContentHash = item.encryptedContentHash
                    lastSyncContentHash = lastSync['encryptedContentHash']
                    if lastSyncContentHash == currentItemContentHash:
                        conflict = False
            if conflict:
                result.conflicts.add((itemId, localVersionId, serverVersionId))
            else:
                yield itemId, lastSync, serverVersionId

    def _updateItemsToVersionFromServer(self, versions, server, cp):
        """ Get Metadata and Content from Server for items. """
        updated = set()
        forbidden = set()
        shareKeys = {}
        for itemId, lastSync, serverVersionId in versions:
            try:
                metaData, contentIt = cp.getItemVersion(
                    itemId, serverVersionId)
            except AccessRestricted:
                # can happen here, if user is allowed to getNewVersionsForItems
                # (every member is) but does not have READ_ITEM
                forbidden.add(itemId)
                continue

            shareId = metaData['shareId']

            itemData = {}
            for k in client.PUBLIC_ITEM_METADATA_FIELDS:
                if k != 'lastModified':
                    itemData[k] = metaData[k]

            if shareId is not None:
                # was shared, server sends all parameters along.
                # The shareKey is encrypted with the local user key,
                # the item with the shareKey
                shareKey = shareKeys.get(shareId, None)
                if not shareKey:
                    shareKey = self._decrypt_with_user_key(
                        metaData['encryptedShareKey'])
                    shareKeys[shareId] = shareKey
                itemKey = utilcrypto.decryptSymmetric(
                    key=shareKey,
                    algorithm=metaData['itemKeyEncryptionMethod'],
                    iv=metaData['itemKeyEncryptionIV'],
                    encryptedData=metaData['encryptedItemKey']
                )
                itemData['encryptedItemKey'] = self._encrypt_with_user_key(
                    itemKey)
            else:
                itemData['encryptedItemKey'] = metaData['encryptedItemKey']
                pass

            self._updateItem(itemData, contentIt)

            time = datetime.datetime.now()
            self.db_setSync(server, itemId, serverVersionId, shareId,
                            metaData['encryptedContentHash'], "pull", time)

            item = self.getItem(itemId)
            logger.info("Item Content Updatedto %s %r" %
                        (serverVersionId, item))
            if lastSync is None:
                lastVersionId = None
            else:
                lastVersionId = lastSync['versionId']
            updated.add((itemId, lastVersionId, serverVersionId))

        return updated, forbidden

    PushResult = collections.namedtuple(
        "PushResult", [
            "conflicts", "updated", "ignored", "forbidden"])
    PushTreeResult = collections.namedtuple(
        "PushTreeResult", [
            "conflicts", "updated", "ignored", "excluded", "forbidden"])

    def synchronizeItemTreeToServer(
            self,
            item,
            server,
            addUnsynced=False,
            addChildrenOfSynced=True):
        """ Synchronize an Item Tree to the server.
            If `addUnsynced` add items that were never synced
            If `addChildrenOfSynced`, add children that were never synced if
            their parent was synced before
            If Item was synced before, the same share id is used, otherwise its
            parents shareId (defaulting to None)"""

        collected_items_with_shares = {}
        excluded_ids = []
        stack = [(False, None)]

        def visit(itemId, item, down, up, **_):
            """ walk through the tree,
                record in stack if parent was synced and its shareid
                append itemId,shareId to collected_items if item should be
                synced,
                otherwise append itemId to excluded_ids.
            """
            if item is None:
                # Item not local
                return False

            if not item.hasContent():
                raise RuntimeError("Can not synchronize Empty Item")

            parent_synced, parent_share = stack[-1]

            # On Down Path, check if item should be synced
            if down:
                # allways sync
                sync = False
                share = None

                if not sync:
                    # if it was synced before, sync again with same share Id
                    syncs = self.db_getSyncs(itemIds=[itemId], server=server)
                    syncs = list(syncs)
                    if len(syncs) > 0:
                        assert len(syncs) == 1
                        syncData = syncs[0]
                        assert syncData['itemId'] == itemId
                        share = syncData['shareId']
                        sync = True

                if not sync:
                    if addChildrenOfSynced:
                        # was never synced but parent was. sync and inherit
                        # parents share
                        sync = parent_synced
                        share = parent_share

                if not sync:
                    if addUnsynced:
                        # was never synced but parent was. sync and inherit
                        # parents share
                        sync = True
                        share = parent_share

                if sync:
                    if itemId in collected_items_with_shares:
                        s = collected_items_with_shares[itemId]
                        if s is not None:
                            if share is not None:
                                if s != share:
                                    raise Exception(
                                        "inherited shares conflict")
                    collected_items_with_shares[itemId] = share
                else:
                    excluded_ids.append(itemId)

                # push on stack on way down
                stack.append((sync, share))

            if up:
                # pop from stack on way up
                stack.pop()

        self.walkItemTree(item, visit)

        pr = self._synchronizeItemIdsToServer(
            collected_items_with_shares.items(),
            server)
        ptr = self.PushTreeResult(
            updated=pr.updated,
            conflicts=pr.conflicts,
            ignored=pr.ignored,
            forbidden=pr.forbidden,
            excluded=excluded_ids
        )
        return ptr

    def _synchronizeItemIdsToServer(self, items, server):
        """ Synchronize a group of items to a server. For every Item the
            share ID is specified. Items that have the same version on the
            server and the same shareId are not changed.
            The ItemKey is encrypted for the share automatically if specified.

            * items - list/iter of tuples (itemId, shareId)
            * server - Server Name
        """
        self._selfCheck()
        cp = self._openClientProtocol(server)
        try:
            iwocs, ignored = self.getItemsWithoutCurrentSync(server, items)
            conflicts, updated, forbidden = self._updateItemsToServer(
                iwocs, server, cp)

            logger.info(
                "Synchronized to Server %s; ItemIds: %r, updated: %r, "
                "conflicts: %r, ignored: %r",
                server,
                items,
                updated,
                conflicts,
                ignored)

            return self.PushResult(conflicts=conflicts, updated=updated,
                                   ignored=ignored, forbidden=forbidden)
        finally:
            cp.close()

    def getItemsWithoutCurrentSync(self, server, items):
        """ for an iter of (itemId, shareId) get the last sync for that itemId
            with `server`. If the item content changed, or the shareId passed
            differs from the one at last sync, return in todo, else in ignored

        """
        iwocs = []
        ignored = set()
        # Work on 100 items at a time
        for group in util.groupwiseIterator(items, 100):
            share_by_itemId = dict(group)
            ids = share_by_itemId.keys()
            for sync in self.db_get_sync_for_items(server, ids):
                itemId = sync['itemId']

                item = self.getItem(itemId)
                if not item.hasContent():
                    raise RuntimeError("Can not synchronize Empty Item")
                upd = False

                if sync['versionId'] is None:
                    upd = True
                    logger.debug("Item %s was never synced", itemId)
                else:
                    ieh = sync['current_hash']
                    seh = sync['last_hash']

                    if ieh != seh:
                        upd = True
                        logger.debug("Item %s: content changed", itemId)

                share = share_by_itemId[itemId]
                if share != sync['shareId']:
                    upd = True
                    logger.debug("Item %s: sync changed: %s -> %s",
                                 itemId, sync['shareId'], share)

                if upd:
                    iwocs.append((itemId, share, sync))
                else:
                    ignored.add((itemId, sync['versionId']))

        return iwocs, ignored

    def _updateItemsToServer(self, iwocs, server, cp):
        """ Send metadata and content of items to server """
        conflicts = set()
        updated = set()
        forbidden = set()
        shares = {}
        for itemId, shareId, sync in iwocs:
            oldVersionId = sync['versionId']
            if oldVersionId is None:
                versioningScheme = self.callbacks.getNewSyncVersioningScheme(
                    itemId, server)
            else:
                versioningScheme = None

            item = self.getItem(itemId)

            metaData = item.getEncryptedMetaData()

            contentIt = item.getEncryptedContentIter()

            itemKey = item._wrapped.encryptionKey

            if shareId is None:
                # for items not shared, encrypt the itemKey with the local
                # user key, same as for local storage
                encryptedItemKey = self._encrypt_with_user_key(itemKey)
                itemKeyEncryptionIV = None
            else:
                share = shares.get(shareId, None)
                if share is None:
                    share, members, myMember = cp.getShare(shareId, True)
                    shareKey = self._decrypt_with_user_key(
                        myMember['EncryptedShareKey'])
                    share['shareKey'] = shareKey
                    shares[shareId] = share, myMember
                else:
                    share, myMember = share

                enc, iv = utilcrypto.encryptSymmetric(
                    plainData=itemKey,
                    key=share['shareKey'],
                    algorithm=share['EncryptionMethod']
                )

                encryptedItemKey = enc
                itemKeyEncryptionIV = iv

            try:
                success, versionId = cp.addItemVersion(
                    encContIter=contentIt,
                    shareId=shareId,
                    itemKeyEncryptionIV=itemKeyEncryptionIV,
                    oldVersionId=oldVersionId,
                    versioningScheme=versioningScheme,
                    encryptedItemKey=encryptedItemKey,
                    **metaData)
            except AccessRestricted:
                logger.warning(
                    "forbidden to send Item %s, last Sync: %s to Server %s",
                    item,
                    oldVersionId,
                    server)
                forbidden.add(itemId)
            else:
                if not success:
                    logger.warning(
                        "Conflict sending Item %s, last Sync: %s to"
                        " Server %s, was rejected because of Version %s",
                        itemId,
                        oldVersionId,
                        server,
                        versionId)
                    conflicts.add((itemId, oldVersionId, versionId))
                else:
                    updated.add((itemId, oldVersionId, versionId))

                    logger.info(
                        "Item %s, was synchronized with server %s new VID: %s",
                        item,
                        server,
                        versionId)
                    ch = metaData['encryptedContentHash']
                    time = datetime.datetime.now()
                    self.db_setSync(
                        server, itemId, versionId, shareId, ch, "push", time)
            finally:
                contentIt.close()

        return conflicts, updated, forbidden

    def addServer(self, name, host, port,
                  fingerprintMethod=None, fingerprint=None, overwrite=False):
        
        """ Add a server, connect to test the server key, ping to see if the
        server authorizes that. Return whether authorized. """

        self._selfCheck()

        if not overwrite:
            try:
                self.db_getServer(name)
            except KeyError:
                pass  # no server with that name yet
            else:
                raise KeyError("Server already exists", name)

        addr = host, port
        if fingerprintMethod is None:
            fingerprintMethod = self.callbacks.getNewServerAsymmetricKeyFingerprintMethod()
        fp = None

        def verifyServerKey(sk):
            nonlocal fp
            fp = utilcrypto.getFingerprintFromAsymmetricKey(
                sk, fingerprintMethod)
            if fingerprint is None:
                b = self.callbacks.verifyNewServerFingerprint(
                        fp, fingerprintMethod)
            else:
                b = fp == fingerprint
            if not b:
                raise ValueError("Server Fingerprint wrong")
            return True

        cs = socket.create_connection(
            addr, self.callbacks.getConnectionTimeout())
        cp = net.ClientProtocol(cs)
        try:
            cp.setup(
                self.getUserPublicKey(),
                self._getUserPrivateKey(),
                verifyServerKey,
                self.callbacks.getConnectionCipherSuites())
            assert fp is not None, "verifyServerKey should change fp"

            try:
                cp.ping()
            except net.AccessRestricted:
                accepted = False
            else:
                accepted = True
        finally:
            cp.close()

        logger.info("Added Server %s, %s:%d. Accepted: %s", name, host,
                    port, accepted)
        self.db_addServer(name, host, port, fp, fingerprintMethod, overwrite)

        return accepted

    def pingServer(self, server):
        """ Ping a server, return round trip time in ms """
        cp = self._openClientProtocol(server)
        try:
            return cp.ping()
        finally:
            cp.close()

    def createShare(self, server, name):
        """ Create a new Share on the server, add Member for self. """

        encryptAlgo = self.callbacks.getNewShareEncryptionAlgorithm()
        macAlgo = self.callbacks.getNewShareMACAlgorithm()
        fpm = self.callbacks.getNewShareFingerprintMethod()

        factory = crypto.getSymmetricEncryptionAlgorithm(encryptAlgo)
        shareKey = crypto.generateSymmetricEncryptionKey(factory.getKeySize())

        serverData = self.db_getServer(server)

        email = self.callbacks.getEmailToUseInShares()

        perms = PermissionSet.ALL

        userPublicKey = self.getUserPublicKey()

        encShareKey = self._encrypt_with_user_key(shareKey)

        fingerprint = utilcrypto.getFingerprintFromAsymmetricKey(userPublicKey,
                                                                 fpm)
        auth = email.lower() + fingerprint
        auth = auth.encode("UTF-8")
        auth = utilcrypto.authenticateMessage(macAlgo, shareKey, auth)

        cp = self._openClientProtocol(server)
        try:
            shareId = cp.createShare(name, encryptAlgo, macAlgo, fpm)
            cp.addShareMember(shareId, email, perms, userPublicKey,
                              encShareKey, auth)
            logger.info("Created Share %d, and added self", shareId)
            return shareId
        finally:
            cp.close()

    def addUserToShare(self, server, shareId, email, perms, userPublicKey):
        cp = self._openClientProtocol(server)
        try:
            share, _, myMember = cp.getShare(shareId, True)
            shareKey = self._decrypt_with_user_key(
                myMember['EncryptedShareKey'])

            encShareKey = utilcrypto.encrypt_asymmetric(
                data=shareKey,
                key=userPublicKey)

            auth = self._authForUserInShare(email, userPublicKey,
                                            shareKey, share)

            cp.addShareMember(shareId, email, perms, userPublicKey,
                              encShareKey, auth)
            logger.info("Added user %s to share %d", email, shareId)
        finally:
            cp.close()

    def addUserToShareFromOtherGroup(self, server, shareId, email, perms,
                                     o_shareId):
        cp = self._openClientProtocol(server)
        try:
            share, members, myMember = cp.getShare(shareId)
            for m in members:
                if m['Email'].lower() == email.lower():
                    raise Exception("Already added")

            o_share, o_members, o_myMember = cp.getShare(o_shareId)

            for o_member in o_members:
                if o_member['Email'].lower() == email.lower():
                    break
            else:
                raise Exception("No user %s in Share %s" % (email, o_shareId))

            o_shareKey = self._decrypt_with_user_key(
                o_myMember['EncryptedShareKey'])

            userPublicKey = o_member['UserPublicKey']
            o_auth = self._authForUserInShare(email, userPublicKey,
                                              o_shareKey, o_share)

            if o_member['MemberAuthentication'] != o_auth:
                raise Exception("Member %s has incorrect Auth in Group %s",
                                email, o_shareId)

            shareKey = self._decrypt_with_user_key(
                myMember['EncryptedShareKey'])

            encShareKey = utilcrypto.encrypt_asymmetric(
                data=shareKey,
                key=userPublicKey)

            auth = self._authForUserInShare(email, userPublicKey,
                                            shareKey, share)

            cp.addShareMember(shareId, email, perms, userPublicKey,
                              encShareKey, auth)
        finally:
            cp.close()

    def _authForUserInShare(self, email, userPublicKey, shareKey, share):
        macAlgo = share['ShareMemberAuthenticationMethod']
        fpm = share['FingerprintMethod']

        fingerprint = utilcrypto.getFingerprintFromAsymmetricKey(
            userPublicKey, fpm)

        auth = email.lower() + fingerprint
        auth = auth.encode("UTF-8")
        auth = utilcrypto.authenticateMessage(macAlgo, shareKey, auth)

        return auth

    def changeShareMemberPermissions(self, server, shareId, email, perms):
        cp = self._openClientProtocol(server)
        try:
            share, members, myMember = cp.getShare(shareId, False)

            for member in members:
                if email.lower() == member['Email'].lower():
                    break
            else:
                raise KeyError("No Member %s in Group %s", email, shareId)

            shareKey = self._decrypt_with_user_key(
                myMember['EncryptedShareKey'])

            auth = self._authForUserInShare(email, member['UserPublicKey'],
                                            shareKey, share)

            if member['MemberAuthentication'] != auth:
                raise Exception("Member %s has incorrect Auth in Group %s",
                                email, shareId)

            cp.updateShareMember(
                shareId=shareId,
                oldPubKey=member['UserPublicKey'],
                email=email,
                permissions=perms,
                userPublicKey=member['UserPublicKey'],
                encShareKey=member['EncryptedShareKey'],
                auth=auth)

            logger.info("Changed user permission for %s in Group %s from %r"
                        "to %r", email, shareId, member['Permissions'], perms)
        finally:
            cp.close()

    def replaceKeyInShareMemberWithOwn(self, server, shareId, repKey):
        """ Replace a (temporary) key in a share group member with own,
            change the email if specified"""

        asymAlgo = crypto.getAsymmetricEncryptionAlgorithm(repKey['algorithm'])
        pubRepKey = asymAlgo.getPublicFromPrivate(repKey)

        # have to connect with that Key
        row = self.db_getServer(server)
        addr = row['host'], row['port']
        cs = socket.create_connection(
            addr, self.callbacks.getConnectionTimeout())
        cp = net.ClientProtocol(cs)

        def verifyServerKey(sk):
            fp = utilcrypto.getFingerprintFromAsymmetricKey(
                sk, row['fingerprintMethod'])
            if fp != row['fingerprint']:
                raise ValueError(
                    "Server Key Mismatch: %s != %s", fp, row['fingerprint'])
            return True

        try:
            cp.setup(pubRepKey, repKey, verifyServerKey,
                     self.callbacks.getConnectionCipherSuites())

            newPubKey = self.getUserPublicKey()

            share, _, myMember = cp.getShare(shareId, True)

            # decrypt shareKey with repKey
            dec = asymAlgo.getDecryptor(repKey)
            shareKey = dec.decrypt(myMember['EncryptedShareKey'])

            macAlgo = share['ShareMemberAuthenticationMethod']
            fpm = share['FingerprintMethod']

            encShareKey = self._encrypt_with_user_key(shareKey)

            email = self.callbacks.getEmailToUseInShares()

            fingerprint = utilcrypto.getFingerprintFromAsymmetricKey(
                newPubKey, fpm)

            auth = email.lower() + fingerprint
            auth = auth.encode("UTF-8")
            auth = utilcrypto.authenticateMessage(macAlgo, shareKey, auth)

            perms = myMember['Permissions']

            cp.updateShareMember(
                shareId=shareId,
                oldPubKey=pubRepKey,
                email=email,
                permissions=perms,
                userPublicKey=newPubKey,
                encShareKey=encShareKey,
                auth=auth)

            logger.info("Replaced Key in Share %s", shareId)

        finally:
            cp.close()

    def getShare(self, server, shareId, forMe=False):
        """ Get the Share group from the Server.
            if `forMe` get only the common data and that for the this client
            else get shareData, Members
        """
        cp = self._openClientProtocol(server)
        try:
            return cp.getShare(shareId, forMe)
        finally:
            cp.close()

    def queryShares(self, server, name=None):
        cp = self._openClientProtocol(server)
        try:
            shares = cp.queryShares(name)
            return shares
        finally:
            cp.close()

    def shareItem(self, server, shareId, item, recursive=True, force=False):
        """ Synchronize all items in the tree rooting in `item` and set the
            shareId of the items. If an item is already shared, it is only
            overwritten if `force`, otherwise they are reported as excluded.
            return a pushtreeResult.
        """
        excluded = set()
        ids = []
        if recursive:
            def visit(itemId, down, **_):
                if down:
                    if not force:
                        syncs = self.db_getSyncs(
                            itemIds=[itemId], server=server)
                        syncs = list(syncs)
                        if len(syncs) > 0:
                            assert len(syncs) == 1
                            syncData = syncs[0]
                            assert syncData['itemId'] == itemId
                            share = syncData['shareId']
                            if share is not None:
                                if share != shareId:
                                    excluded.add((itemId, share))
                                    return False
                    ids.append((itemId, shareId))

            self.walkItemTree(item, visit, False)
        else:
            ids = [(item.itemId, shareId)]

        pr = self._synchronizeItemIdsToServer(ids, server)
        ptr = self.PushTreeResult(
            updated=pr.updated,
            conflicts=pr.conflicts,
            ignored=pr.ignored,
            forbidden=pr.forbidden,
            excluded=excluded
        )
        return ptr

    def db_setSync(
            self,
            server,
            itemId,
            versionId,
            shareId,
            encryptedContentHash,
            direction,
            time):
        cur = self.db.cursor()
        try:
            with self.db:
                cur.execute("""
                    INSERT OR REPLACE INTO sync
                        ( server, itemId, versionId, shareId, encryptedContentHash, direction, time)
                    VALUES
                        ( ?, ?, ?, ?, ?,? ,? )
                    """, (server, itemId, versionId, shareId, encryptedContentHash, direction, time))
        finally:
            cur.close()

    def db_getSyncs(self, itemIds=None, server=None):
        cur = self.db.cursor()
        try:
            sql = """
                SELECT
                    *
                FROM
                    sync
                WHERE
                    1 = 1"""
            params = ()
            if itemIds:
                sql += """
                    AND
                    itemId IN (""" + ",".join(["?"] * len(itemIds)) + """ )
                    """
                params += tuple(itemIds)
            if server:
                sql += """
                    AND
                    server = ?
                    """
                params += (server,)

            cur.execute(sql, params)
            for row in cur:
                yield row
        finally:
            cur.close()

    def db_get_sync_for_items(self, server, item_ids):
        cur = self.db.cursor()
        try:
            sql = """
                SELECT
                    item.itemid,
                    lastmodified,
                    versionId,
                    shareId,
                    item.encryptedContentHash as current_hash,
                    sync.encryptedContentHash as last_hash,
                    sync.time,
                    server
                FROM item
                LEFT JOIN sync ON item.itemId = sync.ItemId AND sync.server = ?
                WHERE
                    1=1
                    """
            params = (server,)
            if not item_ids:
                cur.execute(sql, params)
                for row in cur:
                    yield row
            else:
                sql100 = sql + \
                    " AND item.itemid IN (" + ",".join("?" * 100) + ")"
                for group in util.groupwiseIterator(item_ids, 100):
                    chunck = tuple(group)
                    if len(chunck) == 100:
                        s = sql100
                    else:
                        s = sql + \
                            " AND item.itemid IN (" + \
                            ",".join("?" * len(chunck)) + ")"
                    cur.execute(s, params + chunck)
                    for row in cur:
                        yield row
        finally:
            cur.close()

    def db_addServer(self, name, host, port, fingerprint, fingerprintMethod,
                     overwrite):
        cur = self.db.cursor()
        try:
            if overwrite:
                sql = "INSERT OR REPLACE"
            else:
                sql = "INSERT"
            sql += """ INTO server
                        (name, host, port, fingerprint, fingerprintMethod)
                    VALUES
                        (?,     ?,      ?,      ?,          ?);"""
            with self.db:
                cur.execute(
                    sql, (name, host, port, fingerprint, fingerprintMethod))
        finally:
            cur.close()

    def db_getServer(self, name):
        cur = self.db.cursor()
        try:
            cur.execute(
                "SELECT host, port, fingerprint, fingerprintMethod FROM server WHERE name = ?",
                (name,
                 ))
            r = cur.fetchall()
            if len(r) == 1:
                return r[0]
            else:
                raise KeyError("No Server named " + name)
        finally:
            cur.close()
