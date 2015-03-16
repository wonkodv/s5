"""
    The main part of the server process.
"""

from ..shared import conventions
import re
import configparser
import os
import threading
import io
import datetime
import sys
import socketserver
import logging

from sqlite3 import IntegrityError
from pathlib import Path

from ..shared import serialize
from ..shared import crypto
from ..shared import utilcrypto
from ..shared import messaging
from ..shared import util

from .net import AccessRestricted, ClientError
from . import net
from ..shared.permissions import *

logger = logging.getLogger(__name__)

SERVER_VERSION = 1


def getUtcTime():
    return datetime.datetime.utcnow()


class S5Server():

    """ Controls the server process. Handles initialization, upgrading,
    starting and stopping the Network, ...
    """

    STATE_INITIALIZED = 1
    STATE_NEEDS_UPGRADE = 2
    STATE_NOT_INITIALIZED = 3

    def __init__(self, dataDirectory):
        self.dataPath = Path(dataDirectory)
        self.keyPath = self.dataPath / "private.key"
        self.objectsPath = self.dataPath / "objects"
        self.dbPath = self.dataPath / "database.sqlite"
        self.servingThread = None
        self.netServer = None

        self._loadConfig()

        allPaths = (self.dataPath, self.objectsPath, self.dbPath, self.keyPath)
        if all(map(lambda p: p.exists(), allPaths)):

            log_level = self.config.get('Log', 'Level').upper()
            log_file = self.config.get('Log', 'File')
            if not '/' in log_file:
                log_file = str(dataDirectory / log_file)
            log_format = self.config.get('Log', 'Format')
            logging.basicConfig(
                level=log_level,
                format=log_format,
                filename=log_file
            )

            self.db = ServerDataBase(self.dbPath)
            with self.keyPath.open("rb") as f:
                key = f.read()
            key = serialize.bytesToObj(key)
            assert key['type'] == 'private'
            algo = crypto.getAsymmetricEncryptionAlgorithm(key['algorithm'])
            self.publicKey = algo.getPublicFromPrivate(key)

            self.asymDecryptor = algo.getDecryptor(key)

            if self.db.getSetting('version') == SERVER_VERSION:
                self._initialized = self.STATE_INITIALIZED
            else:
                self._initialized = self.STATE_NEEDS_UPGRADE
        else:
            self._initialized = self.STATE_NOT_INITIALIZED

    def initializeNew(self):
        if not self._initialized == self.STATE_NOT_INITIALIZED:
            raise Exception("Already initialized")
        if self.dataPath.exists():
            raise Exception("Server Data already exists")

        self.dataPath.mkdir(parents=True)
        self.objectsPath.mkdir()

        algo = self.config.get('Server Key', 'Algorithm')
        algo = crypto.getAsymmetricEncryptionAlgorithm(algo)
        key = algo.generatePrivateKey()
        self.publicKey = algo.getPublicFromPrivate(key)
        self.asymDecryptor = algo.getDecryptor(key)

        key = serialize.objToBytes(key)
        with self.keyPath.open("wb") as f:
            f.write(key)

        self.db = ServerDataBase(self.dbPath)
        self.db.createDatabase()
        self._initialized = self.STATE_NEEDS_UPGRADE
        v = self.db.setSetting('version', 0)
        self.upgrade()

    def upgrade(self):
        if not self._initialized == self.STATE_NEEDS_UPGRADE:
            raise Exception("Server does not need upgrade")

        v = self.db.getSetting('version')
        if v > SERVER_VERSION:
            raise Exception("Can not Downgrade")
        if v == SERVER_VERSION:
            raise Exception("Nothing to Upgrade")

        self.db.upgradeDatabase(v)

        if v < 1:
            self.db.setSetting('userkey.fingerprintmethod',
                               self.config.get('User Keys',
                                               'Fingerprint Method'))

        self.db.setSetting('version', SERVER_VERSION)
        self._initialized = self.STATE_INITIALIZED

    def _loadConfig(self):
        config = configparser.ConfigParser(interpolation=None)

        cfg = Path(__file__).parent / 'default.ini'
        with cfg.open('rt') as f:
            config.read_file(f)

        cfg = self.dataPath / 'config.ini'
        try:
            f = cfg.open('rt')
        except FileNotFoundError:
            pass
        else:
            with f:
                config.read_file(f)
        self.config = config

    def _selfCheck(self):
        if self._initialized != self.STATE_INITIALIZED:
            raise Exception("Not Initialized")

    def setup(self, address=None, port=None, ipv6=None):
        self._selfCheck()
        assert self.netServer is None

        if address is None:
            address = self.config.get('Network', 'Address')
        if port is None:
            port = self.config.getint('Network', 'Port')
        if ipv6 is None:
            ipv6 = self.config.getboolean('Network', 'IPv6')

        s = net.NetworkServer(
            self.messageHandlerFactory,
            self.exceptionHandler)

        s.setup(address, port, ipv6)
        self.netServer = s

    def getAddress(self):
        self._selfCheck()
        a = self.netServer.getAddress()
        return a

    def serveInThread(self):
        self._selfCheck()
        assert self.servingThread is None
        self.servingThread = threading.Thread(
            target=self.netServer.serve, name='S5Server Thread')
        self.servingThread.start()

    def stopServingAndJoin(self):
        self._selfCheck()
        self.netServer.shutdown()
        self.servingThread.join()
        self.servingThread = None

    def exceptionHandler(self, socket, address, exception):
        import traceback
        file, line, _, _ = traceback.extract_tb(exception.__traceback__)[-1]
        logger.error("Exception while handling %s: %s:%d:%s",
                     address, file, line, exception, exc_info=True)

    def messageHandlerFactory(self, remoteAddress):
        """ Return new MessageHandlers"""
        self._selfCheck()
        return ServerMessageHandler(
            self.dbPath,
            self.objectsPath,
            remoteAddress,
            self.publicKey,
            self.asymDecryptor,
            self.config)

    def createToken(self, email):
        """ Create an token. The user who submits that token will get an
        account and can create share groups.
        """
        t = crypto.getRandomBytes(self.config.getint('Tokens', 'Size'))
        t = serialize.base64encode(t)
        self.db.addToken(t, email)
        return t

    def close(self):
        if self.servingThread is not None:
            self.stopServingAndJoin()
        if self.netServer is not None:
            self.netServer.close()
            self.netServer = None


class ServerMessageHandler:

    """ Does the actual server Work, runs in the thread used to serve the
    client socket, one instance per client connection.

    responsible for checking client permissions
    """

    def __init__(self, databasePath, objectsPath, remoteAddress, publicKey,
                 decryptor, config):
        self.config = config
        self.db = ServerDataBase(databasePath)
        self.objectsPath = objectsPath
        self.decryptor = decryptor
        self.publicKey = publicKey
        self.logger = logging.getLogger(
            __name__ + ".SMH" + repr(remoteAddress))

    def setProtoCallback(self, cb):
        """ Call functions on pcb to instruct the client protocol to, e.g.
            require a token or a proof of work
        """
        self.pcb = cb

    def _getStorage(self, itemId, versionId):
        """ The place where versions of items are stored on the server """
        return self.objectsPath / itemId[:2] / (itemId + '.' + str(versionId))

    def getCipherSuite(self, accepted):
        s = self.config.get('Network', 'Cipher Suites')
        l = re.split('[,\s]+', s)
        l = [s for s in l if len(s) > 0]

        for cs in l:
            if cs in accepted:
                return cs
        raise ClientError("No acceptable Cipher suite in %s", accepted)

    def decrypt_with_server_key(self, data):
        return self.decryptor.decrypt(data)

    def acceptClientByAddress(self):
        """ Called at first after connection is established.
            Raise AccessRestricted if client ip is not accepted,
            Require ProofOfWork if client ip connected too often.
        """
        # TODO ensure client is from a certain network if configured
        # TODO require Proof of work for too many connects
        return True

    def acceptClientByPublicKey(self, userKey):
        """ Called after the client is authenticated with a public key
            Accept him if he is a member of any group, or in the users table
        """
        fp = utilcrypto.getFingerprintFromAsymmetricKey(
            userKey,
            self.db.getSetting('userkey.fingerprintmethod')
        )

        self.userFingerprint = fp

        acc = self.db.getUserAccount(fp)
        if acc is not None:
            self.logger.info("Client is user %s, %s", acc['email'], fp)
            return True
        else:
            shares = self.db.queryShares(fp)
            shares = list(shares)
            if len(shares) >= 1:
                self.logger.info("Client is in groups %r, %s", shares, fp)
                return True
            else:
                # Must send token next
                self.logger.info("Client is unknown %s", fp)
                return False

    def acceptClientByToken(self, token):
        try:
            success, email = self.db.mapUserByToken(
                self.userFingerprint, token)
            if success:
                logger.info("Mapped client %s to account %s by token %s",
                            self.userFingerprint, email, token)
                return True
            else:
                logger.info("Client %s submitted invalid token %s",
                            self.userFingerprint, token)
        except Exception as e:
            logger.warning("error setting Token: %r", e, exc_info=e)
        return False

    def getServerPublicKey(self):
        """ Send this Key to the Server to identify """
        if not self.publicKey['type'] == 'public':
            raise AssertionError("Not a Public Key")
        return self.publicKey

    # Below methods handle client requests, and need permission checks

    def getNewItemVersions(self, items_with_versions):
        """ Client wants to know which items he has an old version of,
            Allowed for each item only if the client is owner or a member of
            the share group, independant of the exact permissions
        """

        clients_version_by_id = dict(items_with_versions)
        ids = tuple(clients_version_by_id.keys())
        server_versions = self.db.getNewItemVersions(self.userFingerprint, ids)

        for row in server_versions:
            itemId = row['itemId']
            clientV = clients_version_by_id[itemId]
            serverV = row['versionId']
            del clients_version_by_id[itemId]

            authorized = False
            if row['owner'] == self.userFingerprint:
                authorized = True
            elif row['userFingerprint'] is not None:
                assert row['userFingerprint'] == self.userFingerprint
                authorized = True

            # PERMISSION CHECK
            if not authorized:
                yield itemId, "unauthorized"
            elif serverV == clientV:
                self.logger.debug(
                    "Client has current Version %s of %s", clientV, itemId)
            else:
                self.logger.info(
                    "New Version for Item %s: %s", itemId, row['versionId'])
                yield itemId, serverV
        for itemId in clients_version_by_id.keys():
            yield itemId, "unknown"

    def getItemVersion(self, itemId, versionId):
        """ Get an item versions MetaData and Content,
            plus the shareKey encrypted for a user if the item has a share.

            Only allowed if the user is the owner or has read permissions in
            the share group
        """
        row = self.db.getItemVersion(itemId, versionId, self.userFingerprint)

        if row is None:
            raise ClientError("No Item Version %s/%s", itemId, versionId)

        perms = PermissionSet.fromMask(row['permissions'])

        assert row['sharedWithUserFingerprint'] is None or \
            row['sharedWithUserFingerprint'] == self.userFingerprint
        access = False
        if row['owner'] == self.userFingerprint:
            access = "Owner"
        elif READ_ITEMS in perms:
            access = "Shared"

        # PERMISSION CHECK
        if not access:
            logger.warning("Access to getItemVersion not granted, not Owner,"
                           " permissions: %s", perms)
            raise AccessRestricted(itemId, versionId)
        else:
            logger.debug("Access to getItemVersion granted because %s", access)

        self.logger.info(
            "New Version for Item %s: %s", itemId, row['versionId'])
        p = self._getStorage(itemId, versionId)
        size = row['size']

        def contentIter():
            s = size
            with p.open("rb") as f:
                b = f.read(io.DEFAULT_BUFFER_SIZE)
                while len(b) > 0:
                    yield b
                    s = s - len(b)
                    b = f.read(io.DEFAULT_BUFFER_SIZE)

            assert s == 0
        return dict(row), contentIter(), size

    def _ensurePermissionsInGroup(self, shareId, *perms):
        """ raise an Exception if the client does not have all permissions in
        the group"""
        member = self.db.getShareMembers(shareId, self.userFingerprint)
        member = list(member)
        if len(member) == 0:
            raise AccessRestricted("You are not a Member of the"
                                   " Share Group %s", shareId)
        assert len(member) == 1
        member = member[0]

        memberPerms = PermissionSet.fromMask(member['permissions'])

        if not memberPerms.hasAll(*perms):
            raise AccessRestricted("You do not have permissions %r in the"
                                   " Share Group %s", perms, shareId)

    def addItemVersion(self, itemId, oldVersionId, **itemData):
        """ Add new Version to Item, or add Item

            When adding, the new ShareId must be none, or have ADD permissions
            in that group.
            For new Versions, if the share stays the same, owner or WRITE
            Permissions needed, if the shareId becomes none, must AHVE REMOVE
            in OLD, if
            the share Id changes to other, must have add in new group and
            REMOVE in OLD.

            returns success, newVersionId, oldVersionId, contentUnchanged
        """
        if not conventions.isItemId(itemId):
            raise ClientError("Itemid %s invalid", itemId)

        ipd = self.db.getItemPermissionData(itemId, self.userFingerprint)

        if ipd is None:  # item does not yet exist
            if oldVersionId is not None:
                raise ClientError(
                    "Item %s does not exist, but "
                    "Version %s was submitted",
                    itemId,
                    oldVersionId)

            shareId = itemData['shareId']
            if shareId is not None:
                # must have ADD in the specified shareGroup
                # PERMISSION CHECK (newItem)
                self._ensurePermissionsInGroup(shareId, ADD_ITEMS)

            success, vid, offendingVid = self.db.addItem(
                itemId=itemId,
                user=self.userFingerprint,
                time=getUtcTime(),
                **itemData)
            if success:
                logger.info("New Item %s/%d", itemId, vid)
            else:
                logger.debug("Not creating new Item %s, has version %d",
                             itemId, offendingVid)
        else:
            access = False

            oldGroup = ipd['shareId']
            newGroup = itemData['shareId']

            if ipd['itemOwner'] == self.userFingerprint:
                if oldGroup == newGroup:
                    # Is the Owner, does not change the share
                    access = "Owner"
                elif newGroup is None:
                    # is Owner, was shared but unshares
                    access = "Owner UnShare"
                else:
                    # Share Id changes, must have ADD to the new Group
                    self._ensurePermissionsInGroup(newGroup,
                                                   ADD_ITEMS)
                    access = "Owner AddToGroup"
            else:  # not the item Owner
                if oldGroup is None:
                    raise AccessRestricted("Item %s is not shared with you",
                                           itemId)
                elif oldGroup == newGroup:
                    self._ensurePermissionsInGroup(oldGroup, WRITE_ITEMS)
                    access = "Member with WRITE_ITEMS"
                elif newGroup is None:
                    # not the owner, but changes the share Group to None
                    self._ensurePermissionsInGroup(oldGroup, REMOVE_ITEMS)
                    access = "Member with REMOVE_ITEMS unshares"
                else:
                    # not the owner, but changes the share Group to a new Group
                    self._ensurePermissionsInGroup(oldGroup, REMOVE_ITEMS)
                    self._ensurePermissionsInGroup(newGroup, ADD_ITEMS)
                    access = "Member with REMOVE_ITEMS in OLD and ADD_ITEMS in NEW"

            # PERMISSION CHECK (newVersion)
            if not access:
                # should have raise AccessRestricted.
                # some check is missing
                raise Exception("Programming error in permission Check",
                                itemId, itemData, ipd)

            success, vid, offendingVid = self.db.addItemVersion(
                itemId=itemId,
                user=self.userFingerprint,
                time=getUtcTime(),
                oldVersionId=oldVersionId,
                **itemData)
            if success:
                logger.debug("New (inactive) ItemVersion %s/%d", itemId, vid)
            else:
                logger.debug("Not creating new ItemVersion %s, " +
                             "has version %d, not %d",
                             itemId, offendingVid, oldVersionId)

        if success:
            if oldVersionId is not None:
                oldVersion = self.db.getItemVersion(itemId, oldVersionId)
                oh = oldVersion['encryptedContentHash']
                nh = itemData['encryptedContentHash']
                if oh == nh:  # Content unchanged, activate now
                    so = self._getStorage(itemId, oldVersionId)
                    sn = self._getStorage(itemId, vid)
                    os.link(str(so), str(sn))
                    success, offendingVid = self.db.activateVersion(
                        itemId,
                        vid,
                        oldVersion['size'],
                        oldVersionId)
                    if success:
                        logger.debug("Immediately Activated ItemVersion %s/%d",
                                     itemId, vid)
                        return True, vid, None, True
                    else:
                        return False, None, offendingVid, None
            return True, vid, None, False
        else:
            return False, None, offendingVid, None

    def storeItemVersionData(
            self,
            dataIter,
            itemId,
            newVersionId,
            oldVersionId=None):
        # only called after addItemVersion or addItem, no need for
        # sanitychecks/permission Checks
        s = self._getStorage(itemId, newVersionId)
        if not s.parent.exists():
            s.parent.mkdir(parents=True)
        size = 0
        with s.open('wb') as f:
            for c in dataIter:
                size = size + len(c)
                f.write(c)

        success, vid = self.db.activateVersion(
            itemId, newVersionId, size, oldVersionId)
        if success:
            logger.info(
                "Updated, activating ItemVersion %s/%d", itemId, newVersionId)
            return True, None
        else:
            # somone else was faster, discard and return theoffending vid
            logger.debug("Not activating ItemVersion %s/%d", itemId, vid)
            s.unlink()
            self.db.deleteInactiveItemVersion(itemId, newVersionId)
            return False, vid  # return vid unknown to client

    def createShare(
            self,
            name,
            encryptionMethod,
            macMethod,
            fingerprintMethod):
        """ Create a new Share Group, allowed to all clients with an account """
        try:
            acc = self.db.getUserAccount(self.userFingerprint)
            if acc is None:
                raise AccessRestricted("Only registered users can create"
                                       "share groups.")
            shareId = self.db.createShare(
                encryptionMethod=encryptionMethod,
                name=name,
                macMethod=macMethod,
                fingerprintMethod=fingerprintMethod,
                owner=self.userFingerprint
            )
        except IntegrityError:
            raise ClientError("Share Name not Unique %s", name)
        logger.info("Created new Share %d", shareId)
        return shareId

    def addShareMember(self, **data):
        """ Add/Modify a group Member.
            allowed to the owner,
        """

        shareId = data['shareId']
        share = self.db.getShareById(shareId)

        # PERMISSION CHECK
        if share['owner'] != self.userFingerprint:
            raise AccessRestricted("You are not the Owner of "
                                   "Share Group %s", shareId)

        data['userFingerprint'] = utilcrypto.getFingerprintFromAsymmetricKey(
            data['userPublicKey'],
            self.db.getSetting('userkey.fingerprintmethod'))
        data['userPublicKey'] = serialize.objToStr(data['userPublicKey'])

        data['permissions'] = data['permissions'].toMask()

        logger.info("Adding shareMember %s/%s", data['shareId'],
                    data['userFingerprint'])
        self.db.addShareMember(data)

    def updateShareMember(self, oldKey, **data):
        """ Change a Group Member.

            Allowed to the Group Owner
            and to theMember himself if permissions do not increase
        """
        oldFpr = utilcrypto.getFingerprintFromAsymmetricKey(
            oldKey,
            self.db.getSetting('userkey.fingerprintmethod')
        )
        newFpr = utilcrypto.getFingerprintFromAsymmetricKey(
            data['userPublicKey'],
            self.db.getSetting('userkey.fingerprintmethod')
        )
        data['newUserFingerprint'] = newFpr
        data['oldUserFingerprint'] = oldFpr
        shareId = data['shareId']

        member = list(self.db.getShareMembers(shareId, oldFpr))
        if len(member) == 0:
            member = None
        else:
            assert len(member) == 1
            member = member[0]

        if oldFpr == self.userFingerprint:
            if member is None:
                raise AccessRestricted("You are not a member of Group"
                                       " %s", shareId)
            oldPerms = PermissionSet.fromMask(member['permissions'])
            newPerms = data['permissions']
            # PERMISSION CHECK (Member)
            if not oldPerms.hasAll(*newPerms):
                raise AccessRestricted("You can not increase your permissions"
                                       " in Group %s", shareId)
            logger.info("User updates own Member Record in %s, %s-> %s",
                        shareId, oldFpr, newFpr)
        else:
            # PERMISSION CHECK (Owner)
            share = self.db.getShareById(shareId)
            if share['owner'] != self.userFingerprint:
                raise AccessRestricted(
                    "You are not the Owner of Group %s", shareId)

            if member is None:
                raise ClientError("No Member with that Key in your Group %s",
                                  shareId)
                logger.info("Group Owner Modifys Member %s: %s->%s", shareId,
                            oldFpr, newFpr)

        data['userPublicKey'] = serialize.objToStr(data['userPublicKey'])
        data['permissions'] = data['permissions'].toMask()

        self.db.updateShareMember(data)

    def getShare(self, shareId, forMe):
        """ Get Info about the Share and Members.
            if `forMe` only the own membership.

            `forMe` allowed to every Member,
            otherwise only to members with LIST_MEMBERS
        """

        if forMe:
            userFingerprint = self.userFingerprint
            logger.info(
                "Getting own ShareData for user %d %s",
                shareId,
                userFingerprint)
        else:
            userFingerprint = None
            logger.info(
                "Getting complete ShareData for user %d %s",
                shareId,
                userFingerprint)

        try:
            with self.db:
                shareData = self.db.getShareById(shareId)
                shareMembers = self.db.getShareMembers(
                    shareId, userFingerprint)
        except KeyError:
            # Dont release information if that group exists
            raise AccessRestricted("You are not member of Group %s", shareId)

        def memberKeys(m):
            m = dict(m)
            m['userPublicKey'] = serialize.strToObj(m['userPublicKey'])
            return m

        shareMembers = list(map(memberKeys, shareMembers))

        # PERMISSION CHECK
        if forMe:
            if len(shareMembers) == 0:
                # client is not member of the Group
                raise AccessRestricted("You are not member of Group %s",
                                       shareId)
            assert len(shareMembers) == 1
            return shareData, shareMembers
        else:
            self._ensurePermissionsInGroup(shareId, LIST_MEMBERS)

        return shareData, shareMembers

    def queryShares(self, name=None):
        """ Get a list of share Ids where the user is member of, possibly by
        name). Allowed to anyone"""
        ids = self.db.queryShares(self.userFingerprint, name)
        return list(ids)

    def close(self):
        self.db.close()


class ServerDataBase(util.CommonDatabase):

    """ The database where the server stores information """

    def upgradeDatabase(self, fromVersion):
        if fromVersion < 1:
            with self.db:
                self.db.executescript("""
                CREATE TABLE item(
                    itemId STRING NOT NULL PRIMARY KEY,
                    owner STRING NOT NULL,
                    versioningScheme STRING,
                    newestVersionId INT
                );

                CREATE TABLE itemVersion (
                    versionId INT NOT NULL,
                    itemId  STRING NOT NULL,

                    active BOOL NOT NULL,

                    user STRING NOT NULL,

                    shareId INT,
                    itemKeyEncryptionIV STRING,
                    encryptedItemKey STRING NOT NULL,

                    size INT,
                    encryptionMethod STRING NOT NULL,
                    contentEncryptionIV STRING,
                    encryptedContentType    STRING NOT NULL,
                    typeEncryptionIV STRING,
                    encryptedContentHash STRING,
                    hashEncryptionIV STRING,
                    hashMethod STRING NOT NULL,
                    compressionMethod STRING NOT NULL,
                    time DATETIME NOT NULL,


                    PRIMARY KEY(versionId,itemId)
                );

                CREATE TABLE shareGroup (
                    shareId INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner STRING NOT NULL,
                    name STRING NOT NULL,
                    encryptionMethod STRING NOT NULL,
                    macMethod STRING NOT NULL,
                    fingerprintMethod STRING NOT NULL,

                    UNIQUE (owner, name)
                );

                CREATE TABLE shareMember (
                    shareId INT NOT NULL,
                    permissions INT NOT NULL,
                    userFingerprint STRING NOT NULL,

                    userPublicKey STRING NOT NULL,

                    email STRING NOT NULL,
                    shareKeyForUser STRING NOT NULL,
                    auth STRING NOT NULL,

                    PRIMARY KEY (shareID, userFingerprint)
                );

                """)
        if fromVersion < 2:
            # add useraccounts and Tokens
            self.db.executescript("""
                CREATE TABLE account (
                    fingerprint STRING NOT NULL PRIMARY KEY,
                    email STRING NOT NULL
                );

                CREATE TABLE token (
                    token STRING NOT NULL PRIMARY KEY,
                    email STRING NOT NULL
                );
                """)

    def getItemPermissionData(self, itemId, userFingerprint):
        cur = self.db.cursor()
        try:
            cur.execute("""
                SELECT
                    item.owner as itemOwner,
                    iv.shareId as shareId,
                    sg.owner as ShareOwner,
                    permissions
                FROM
                    item
                    LEFT JOIN itemVersion iv ON
                        item.newestVersionId = iv.versionID
                        AND
                        item.itemId = iv.itemId
                    LEFT JOIN shareGroup sg ON sg.shareId = iv.shareId
                    LEFT JOIN shareMember sm ON sm.shareId = sg.shareId AND
                        sm.userFingerprint = ?
                WHERE
                    item.itemId = ?
                    """, (userFingerprint, itemId))
            rows = cur.fetchall()
            if len(rows) == 0:
                return None
            assert len(rows) == 1
            row = rows[0]
            return row
        finally:
            cur.close()

    def getItemVersion(self, itemId, versionId, userFingerprint=None):
        """ Get the Version for an item, integrating (if userFingerprint is
            provided) the relevant share-data the client needs to decrypt the
            item
        """
        cur = self.db.cursor()
        try:
            cur.execute("""
                SELECT
                    v.*,
                    i.owner,
                    m.shareKeyForUser as encryptedShareKey,
                    m.permissions,
                    s.encryptionMethod as itemKeyEncryptionMethod,
                    m.userFingerprint as sharedWithUserFingerprint
                FROM
                    item i
                    JOIN itemVersion v USING (itemId)
                    LEFT JOIN shareGroup s USING (shareId)
                    LEFT JOIN shareMember as m ON (
                        m.shareId = v.shareId
                        AND
                        m.userFingerprint = ?
                    )
                WHERE
                    itemId = ?
                    AND
                    versionId = ?
                    """, (userFingerprint, itemId, versionId))
            rows = cur.fetchall()
            if len(rows) == 1:
                row = rows[0]
                return row
            assert len(rows) == 0
            return None
        finally:
            cur.close()

    def getNewItemVersions(self, userFingerprint, itemIds):
        """ Get the newest version id for all passed items, and, for permission
        check, the owner and the users share member record if one"""
        cur = self.db.cursor()
        try:
            ph = ",".join(["?"] * len(itemIds))
            cur.execute("""
                SELECT
                    i.itemId,
                    versionId,
                    owner,
                    permissions,
                    userFingerprint
                FROM
                    item i
                    JOIN itemVersion v ON
                        v.itemId = i.itemId
                        AND
                        v.versionId = i.newestVersionId
                    LEFT JOIN shareMember m ON
                        m.shareId = v.shareId
                        AND
                        m.userFingerprint = ?
                WHERE
                    i.itemId IN (""" + ph + """)
                    """, (userFingerprint,) + itemIds)
            rows = cur.fetchall()
            return rows
        finally:
            cur.close()

    def addItem(self, **itemData):
        """
        returns success,newvid,offendingVid"""
        keys = (
            'versionId',
            'itemId',
            'shareId',
            'itemKeyEncryptionIV',
            'encryptedItemKey',
            'encryptionMethod',
            'contentEncryptionIV',
            'encryptedContentType',
            'typeEncryptionIV',
            'encryptedContentHash',
            'hashEncryptionIV',
            'hashMethod',
            'compressionMethod',
            'time',
            'user'
        )
        cur = self.db.cursor()
        try:
            with self.db:
                cur.execute(
                    "SELECT newestVersionId FROM item WHERE itemId = :itemId",
                    itemData)
                x = cur.fetchone()
                if x is not None:
                    return False, None, x['newestVersionId']

                versionId = 1

                itemData['versionId'] = versionId
                itemData['owner'] = itemData['user']

                for k in keys:
                    itemData[k]  # DEBUG: raises KeyError for missing params

                cur.execute("""
                    INSERT INTO itemVersion
                        ( active, """ + ", ".join(keys) + """ )
                    VALUES
                        ( 0, :""" + ",:".join(keys) + """ )
                        """, itemData)

                cur.execute("""
                    INSERT INTO item
                        ( itemId, owner, versioningScheme, newestVersionId )
                    VALUES
                        (:itemId,:owner,:versioningScheme, NULL )
                        """, itemData)
                return True, versionId, None
        finally:
            cur.close()

    def addItemVersion(self, oldVersionId, **itemData):
        """ Add Item Version and set item.newestVersionId, retrun the new version
        IF oldVersionId is the current item.newestVersionId,
        otherwise return item.newestVersionId.

        returns success,newvid,offendingVid"""

        keys = (
            'itemId',
            'versionId',
            'time',
            'user',
            'shareId',
            'itemKeyEncryptionIV',
            'encryptedItemKey',
            'encryptionMethod',
            'contentEncryptionIV',
            'encryptedContentType',
            'typeEncryptionIV',
            'encryptedContentHash',
            'hashEncryptionIV',
            'hashMethod',
            'compressionMethod',
        )
        cur = self.db.cursor()
        try:
            with self.db:
                # Test if client has the newest:
                cur.execute(
                    "SELECT newestVersionId FROM item WHERE itemId = :itemId",
                    itemData)
                versionId = cur.fetchone()[0]
                if versionId is not None and versionId != oldVersionId:
                    return False, None, versionId

                # Select a new one that was never used for the item
                cur.execute(
                    "SELECT MAX(versionId) FROM itemVersion WHERE itemId = :itemId",
                    itemData)
                versionId = cur.fetchone()[0]

                if versionId is None:
                    versionId = 1
                else:
                    versionId = versionId + 1

                itemData['versionId'] = versionId

                for k in keys:
                    itemData[k]  # DEBUG: raises KeyError for missing params
                cur.execute("""
                    INSERT INTO itemVersion
                        (active, """ + ", ".join(keys) + """ )
                    VALUES
                        (0, :""" + ",:".join(keys) + """ )
                        """, itemData)
                return True, versionId, None
        finally:
            cur.close()

    def activateVersion(self, itemId, newVersionId, size, oldVersionId=None):
        cur = self.db.cursor()
        try:
            with self.db:
                cur.execute(
                    "SELECT newestVersionId FROM item WHERE itemId = ?", (itemId,))
                version = cur.fetchone()
                assert version
                assert not cur.fetchone()
                versionId = version['newestVersionId']
                if versionId != oldVersionId:
                    return False, versionId

                cur.execute("""
                    UPDATE itemVersion
                    SET active = 1,
                        size = ?
                    WHERE itemId = ? AND versionId = ? AND active = 0
                        """, (size, itemId, newVersionId))
                assert cur.rowcount == 1
                cur.execute("""
                    UPDATE item
                    SET newestVersionId = ?
                    WHERE itemId = ?
                        """, (newVersionId, itemId,))
                return True, None
        finally:
            cur.close()

    def deleteInactiveItemVersion(self, itemId, versionId):
        cur = self.db.cursor()
        try:
            with self.db:
                cur.execute(
                    "SELECT newestVersionId FROM item WHERE itemId = ?", (itemId,))
                newestVersionId = cur.fetchone()['newestVersionId']
                if newestVersionId == versionId:
                    raise Exception("Can not delete the active Version")
                cur.execute("""
                    DELETE FROM itemVersion
                    WHERE itemId = ? AND versionId = ? AND active = 0
                        """, (itemId, versionId,))
                assert cur.rowcount == 1
        finally:
            cur.close()

    def createShare(self, **data):
        cur = self.db.cursor()
        try:
            with self.db:
                cur.execute("""
                    INSERT INTO shareGroup
                        ( owner, name, encryptionMethod, macMethod, fingerprintMethod)
                    VALUES
                        (:owner,:name,:encryptionMethod,:macMethod,:fingerprintMethod)
                        """, data)
            shareId = cur.lastrowid
            return shareId
        finally:
            cur.close()

    def addShareMember(self, data):
        keys = (
            'shareId',
            'userFingerprint',
            'email',
            'permissions',
            'userPublicKey',
            'shareKeyForUser',
            'auth',
        )
        cur = self.db.cursor()
        try:
            for k in keys:
                data[k]  # DEBUG
            with self.db:
                cur.execute("""
                    INSERT INTO shareMember
                        (""" + ", ".join(keys) + """ )
                    VALUES
                        (:""" + ",:".join(keys) + """ )
                        """, ( data ) )
        finally:
            cur.close()

    def updateShareMember(self, data):
        cur = self.db.cursor()
        try:
            with self.db:
                cur.execute("""
                    UPDATE shareMember SET
                        userFingerprint = :newUserFingerprint,
                        email = :email,
                        permissions = :permissions,
                        userPublicKey = :userPublicKey,
                        shareKeyForUser = :shareKeyForUser,
                        auth = :auth
                    WHERE
                        shareId = :shareId
                        AND
                        userFingerprint = :oldUserFingerprint
                        """, ( data ) )
        finally:
            cur.close()

    def getShareById(self, shareId):
        cur = self.db.cursor()
        try:
            cur.execute("""
                SELECT
                    g.*,
                    m.email as ownerEmail
                FROM
                    shareGroup g
                    LEFT JOIN shareMember m ON
                        m.shareId = g.shareID
                        AND
                        m.userFingerprint = g.owner
                WHERE
                    g.shareId = ?
                    """, (shareId,))
            rows = cur.fetchall()
            if len(rows) == 1:
                return rows[0]
            assert len(rows) == 0
            raise KeyError(shareId)

        finally:
            cur.close()

    def getShareMembers(self, shareId, userFingerprint=None):
        cur = self.db.cursor()
        try:
            sql = """
                SELECT
                    *
                FROM
                    shareMember
                WHERE
                    shareId = ?
                    """
            params = (shareId,)
            if userFingerprint:
                sql += """
                    AND
                    userFingerprint = ?"""
                params += (userFingerprint,)

            cur.execute(sql, params)
            for row in cur:
                yield row
        finally:
            cur.close()

    def queryShares(self, userFingerprint, name=None):
        cur = self.db.cursor()
        try:
            sql = """
                SELECT
                    shareId
                FROM
                    shareGroup g
                WHERE
                    ? in (
                        SELECT userFingerprint
                        FROM shareMember m
                        WHERE g.shareId = m.shareId
                    )
                    """
            params = (userFingerprint,)
            if name:
                sql += """
                    AND
                    name = ?"""
                params += (name,)

            cur.execute(sql, params)
            for row in cur:
                yield row['shareId']
        finally:
            cur.close()

    def addToken(self, token, email):
        """ Create an account that can be taken over by a user that has the
        token"""
        cur = self.db.cursor()
        with self.db:
            cur.execute("""
                INSERT INTO token
                    (token, email)
                VALUES
                    ( ?, ?) """,
                        (token, email))

    def mapUserByToken(self, userFingerprint, token):
        """ Create an account based on a token. delete the token. """
        cur = self.db.cursor()
        with self.db:
            cur.execute("SELECT email FROM token WHERE token = ?", (token,))
            email = cur.fetchall()
            if len(email) == 0:
                return False, None
            assert len(email) == 1
            email = email[0]['email']
            cur.execute("""
                INSERT INTO account
                    (fingerprint, email)
                VALUES
                    ( ?, ?) """,
                        (userFingerprint, email))
            cur.execute(""" DELETE FROM token WHERE token = ?""", (token, ))
            return True, email

    def getUserAccount(self, userFingerprint):
        cur = self.db.cursor()
        cur.execute("SELECT * from account WHERE fingerprint = ?",
                    (userFingerprint, ))
        l = cur.fetchall()
        if len(l) == 0:
            return None
        assert len(l) == 1
        return l[0]
