"""
This Module provides the core functionallity to store retrieve and find items.

S5Client handles the item Storage.
IterationMixin allows walking item structures.
CatalogMixin organizes a directory like structure to find items

"""

import shutil
import inspect
import datetime
import re
import weakref
import logging
import sqlite3

from . import items
from ..shared import crypto
from ..shared import conventions
from ..shared import serialize
from ..shared import util
from ..shared import utilcrypto

from ..shared.conventions import ITEM_TYPES
from .items import PUBLIC_ITEM_METADATA_FIELDS

logger = logging.getLogger(__name__)

# Incremented with future versions if the data model must be changed
CLIENT_VERSION = 1

class S5Client:

    """ Base Client, that handles the items, creation of a sqlite database,
    initialization and upgrade Mamagement. """

    STATE_INITIALIZED = 1
    STATE_NEEDS_UPGRADE = 2
    STATE_NOT_INITIALIZED = 3

    def __init__(self, callbacks):
        self.callbacks = callbacks

        self.datadir = callbacks.getDataDirectory()

        self.objectsdir = self.datadir / 'objects'
        self.databasePath = self.datadir / 'db.sqlite'
        self.userKeyPath = self.datadir / 'userkey'

        self.items = {}
        self.userKey = None
        self._upgrade_in_progress = False

        # Test if everything is present, set _initialized according.
        # _selfCheck() will test for this, raising exceptions on any public
        # method call that can not be performed.

        if all(map(lambda p: p.exists(),
                   (self.datadir,
                    self.objectsdir,
                    self.databasePath,
                    self.userKeyPath))):
            self.db = util.CommonDatabase(self.databasePath)

            classes = self._getclassdescription()
            storedClasses = self.db.getSetting('client.classes')
            assert classes == storedClasses, (
                "Initialized for another Type %s!=%s" %
                (storedClasses, classes)
            )

            if self.db.getSetting('version') == CLIENT_VERSION:
                self._initialized = self.STATE_INITIALIZED
            else:
                self._initialized = self.STATE_NEEDS_UPGRADE
        else:
            self._initialized = self.STATE_NOT_INITIALIZED

    # Initialization and Upgrade:
    def initializeWithExistingKey(self, importKey):
        """ Called by the User of the Client to set up the Directory,
            initialize Database, ... before the first time that the client can
            be used in that directory.

            Import the userKey
        """
        if not self._initialized == self.STATE_NOT_INITIALIZED:
            raise Exception("Client already initialized")
        if self.datadir.exists():
            raise Exception("Client already initialized")

        self._upgrade_in_progress = True

        self.datadir.mkdir(parents=True)
        try:
            self.objectsdir.mkdir()

            if importKey is None:
                self._generateAndStoreUserKey()
            else:
                self._importUserKey(importKey)

            self.db = util.CommonDatabase(self.databasePath)
            self.db.createDatabase()

            self.db.setSetting('client.classes', self._getclassdescription())
            self.db.setSetting('version', 0)

            self._initialized = self.STATE_NEEDS_UPGRADE

            self.upgrade()
        except:
            shutil.rmtree(str(self.datadir))
            raise

    def initializeNew(self):
        """ Called by the User of the Client to set up the Directory,
            initialize Database, ... before the first time that the client can
            be used in that directory.
        """
        self.initializeWithExistingKey(None)

    def _do_upgrade(self, fromVersion):
        """ Do the upgrading, can be implemented by plugins, but they must call
        super()
        """
        if fromVersion < 1:
            c = self.db.cursor()
            try:
                c.executescript("""
                    CREATE TABLE item (
                        itemId STRING PRIMARY KEY,
                        lastmodified TIMESTAMP,

                        encryptedItemKey STRING NOT NULL,

                        hashMethod STRING NOT NULL,
                        encryptionMethod STRING NOT NULL,
                        compressionMethod STRING NOT NULL,

                        sizeOfEncryptedContent INT,
                        contentEncryptionIV STRING,

                        encryptedContentType STRING NOT NULL,
                        typeEncryptionIV STRING NOT NULL,

                        hashEncryptionIV STRING,
                        encryptedContentHash STRING
                    );

                    """)
            finally:
                c.close()

        self._initialized = self.STATE_INITIALIZED

    def upgrade(self):
        """ Called by the User of the client before using that client in a
            directory the first time since the software was updated. Mixins can
            implement _do_upgrade(self,lastVersion) but have to call
            super()._do_upgrade(lastVersion). The version is 0 when initializeNew()
            was called
        """

        if not self._initialized == self.STATE_NEEDS_UPGRADE:
            raise Exception("Client not upgradeable")
        self._upgrade_in_progress = True

        v = self.db.getSetting('version')

        if v > CLIENT_VERSION:
            raise Exception("Can not Downgrade")
        if v == CLIENT_VERSION:
            raise Exception("Nothing to Upgrade")

        self._do_upgrade(v)

        assert self._initialized == self.STATE_INITIALIZED, (
            "Some Mixin did " "not call super()._do_upgrade(v) ")

        self.db.setSetting('version', CLIENT_VERSION)
        self._upgrade_in_progress = False

    def _selfCheck(self):
        """ Test that the client was properly set up and upgraded """
        if self._initialized != self.STATE_INITIALIZED:
            if not self._upgrade_in_progress:
                raise Exception("Not Initialized")

    def _getclassdescription(self):
        """ return a string that represents the class with all its mixins """
        classes = inspect.getmro(type(self))
        classes = "".join(map(str, classes))
        return classes

    # Private Key:

    def _getUserPrivateKey(self):
        """ load the user private key from disk, decrypt it """
        if self.userKey is None:
            assert self.userKeyPath.exists()
            with self.userKeyPath.open('rb') as f:
                b = f.read()
            password = self.callbacks.askForUserKeyPassword()
            data = utilcrypto.extractPasswordProtectedData(b, password)
            key = serialize.bytesToObj(data)
            assert key['type'] == 'private'
            self.userKey = key
        return self.userKey

    def _generateAndStoreUserKey(self):
        """ Generate a key for this user, store it passwordprotected """
        password = self.callbacks.askForNewUserKeyPassword()
        algo = self.callbacks.getNewUserKeyAlgorithm()
        sAlgo = self.callbacks.getNewUserKeyProtectionAlgorithm()
        pbkdf = self.callbacks.getNewUserKeyProtectionPBKDF()

        impl = crypto.getAsymmetricEncryptionAlgorithm(algo)
        key = impl.generatePrivateKey()

        self.userKey = key

        data = serialize.objToBytes(key)
        pd = utilcrypto.passwordProtectData(data, password, sAlgo, pbkdf)
        with self.userKeyPath.open('wb') as f:
            f.write(pd)

    def _importUserKey(self, importKey):
        importPasswd = self.callbacks.askForPasswordToImportUserKey()
        data = utilcrypto.extractPasswordProtectedData(importKey, importPasswd)
        key = serialize.bytesToObj(data)
        if not key['type'] == 'private':
            raise TypeError("Not a private Key")
        self.userKey = key

        password = self.callbacks.askForNewUserKeyPassword()
        algo = self.callbacks.getNewUserKeyAlgorithm()
        sAlgo = self.callbacks.getNewUserKeyProtectionAlgorithm()
        pbkdf = self.callbacks.getNewUserKeyProtectionPBKDF()

        pd = utilcrypto.passwordProtectData(data, password, sAlgo, pbkdf)
        with self.userKeyPath.open('wb') as f:
            f.write(pd)

    def exportUserKey(self):
        pw = utilcrypto.generatePassword(
                self.callbacks.getUserKeyExportPasswordLength())

        key = self._getUserPrivateKey()
        data = serialize.objToBytes(key)

        algo = self.callbacks.getNewUserKeyAlgorithm()
        sAlgo = self.callbacks.getNewUserKeyProtectionAlgorithm()
        pbkdf = self.callbacks.getNewUserKeyProtectionPBKDF()

        exportData = utilcrypto.passwordProtectData(
            data, pw, sAlgo, pbkdf)

        return exportData, pw

    def getUserPublicKey(self):
        """ Get the public portion of the users private Key """
        dk = self._getUserPrivateKey()
        a = crypto.getAsymmetricEncryptionAlgorithm(dk['algorithm'])
        p = a.getPublicFromPrivate(dk)
        self.userPublicKey = p
        return p

    def _encrypt_with_user_key(self, data):
        """ encrypt data (a symmetric key) with the user's key.
            data must be small enough so the userKey can encrypt it (see
            s5.crypto)"""
        pub = self.getUserPublicKey()
        a = crypto.getAsymmetricEncryptionAlgorithm(pub['algorithm'])
        e = a.getEncryptor(pub)
        encryptedItemKey = e.encrypt(data)

        return encryptedItemKey

    def _decrypt_with_user_key(self, encryptedItemKey):
        """ decrypt data that was encrypted with the user key """
        k = self._getUserPrivateKey()
        a = crypto.getAsymmetricEncryptionAlgorithm(k['algorithm'])
        d = a.getDecryptor(k)
        decryptedKey = d.decrypt(encryptedItemKey)
        return decryptedKey

    # Item Handling:
    def _rememberItem(self, item):
        """ cache items for faster getItem() """
        self.items[item.itemId] = weakref.ref(item)

    def getItemStorage(self, itemId):
        """ Where ItemContents are stored """
        self._selfCheck()
        p = self.objectsdir / itemId[0:2] / itemId
        return p

    def getItem(self, itemId):
        """ Get an Item, wrapped in an accessor by its itemId """
        self._selfCheck()
        if itemId in self.items:
            # cached so there is only 1 accessor per itemId
            # using weakref allows items that noone else has to get garbage
            # collected
            itemRef = self.items[itemId]
            item = itemRef()
            if item is not None:
                return item

        row = self.db_getItem(itemId)
        if row is None:
            raise KeyError("no item with itemId %s", itemId)
        else:
            params = dict((k, row[k])
                          for k in items.PUBLIC_ITEM_METADATA_FIELDS)

            key = self._decrypt_with_user_key(row['encryptedItemKey'])

            itm = items.makeOldItem(
                saver=self,
                storage=self.getItemStorage(row['itemid']),
                encryptionKey=key,
                **params
            )
            self._rememberItem(itm)
            return itm

    def newItem(self, contentType):
        """ Make a new item. Will have no content. 
        the accessor to the new item is returned."""
        self._selfCheck()

        itemId = crypto.getRandomItemIdentifier()
        p = self.getItemStorage(itemId)
        if not p.parent.exists():
            p.parent.mkdir()

        em = self.callbacks.getNewItemEncryptionMethod()

        accessor = items.makeNewItem(
            itemId=itemId,
            contentType=contentType,
            storage=p,
            saver=self,
            hashMethod=self.callbacks.getNewItemHashMethod(),
            encryptionMethod=em,
            compressionMethod=self.callbacks.getNewItemCompressionMethod(),
        )
        self._rememberItem(accessor)
        data = accessor.getEncryptedMetaData()
        data['encryptedItemKey'] = self._encrypt_with_user_key(
            accessor._wrapped.encryptionKey)
        self.db_addItem(data)
        return accessor

    def saveItem(self, item):
        self._selfCheck()
        data = item.getEncryptedMetaData()
        data['encryptedItemKey'] = self._encrypt_with_user_key(
            item.encryptionKey)
        self.db_saveItem(data)

    def _updateItem(self, metaData, contentIter):
        itemId = metaData['itemId']
        try:
            accessor = self.getItem(itemId)
        except KeyError:
            new = True
        else:
            new = False
            accessor.beginUpdate()

        storage = self.getItemStorage(itemId)
        p = storage.parent
        if not p.exists():
            storage.parent.mkdir(parents=True)
        # Write to temp File
        tmp = storage.with_suffix(".temp")
        with tmp.open("wb") as f:
            for c in contentIter:
                f.write(c)

        metaData['lastModified'] = datetime.datetime.now()

        if new:
            self.db_addItem(metaData)
        else:
            self.db_saveItem(metaData)

        tmp.replace(storage)

        if not new:
            key = metaData['encryptedItemKey']
            del metaData['encryptedItemKey']
            key = self._decrypt_with_user_key(key)
            item = items.makeOldItemWithoutWrap(
                saver=self,
                storage=storage,
                encryptionKey=key,
                **metaData)
            accessor.endUpdate(item)

    def db_getItem(self, itemId):
        cur = self.db.cursor()
        try:
            cur.execute("SELECT * FROM item WHERE itemId = ?", (itemId,))
            r = cur.fetchall()
            if len(r) == 1:
                row = r[0]
                assert row['lastModified'] is None or isinstance(
                    row['lastModified'],
                    datetime.datetime)
                return r[0]
        finally:
            cur.close()

    def db_addItem(self, itemData):
        keys = items.PUBLIC_ITEM_METADATA_FIELDS + ("encryptedItemKey",)
        cur = self.db.cursor()
        try:
            cur.execute("""
                INSERT INTO item
                    ( """ + ", ".join(keys) + """ )
                VALUES
                    ( :""" + ",:".join(keys) + """ )
                    """, itemData)
            self.db.commit()
        finally:
            cur.close()

    def db_saveItem(self, item):
        keys = items.PUBLIC_ITEM_METADATA_FIELDS + ("encryptedItemKey",)
        keys = set(keys)
        keys.remove('itemId')

        cur = self.db.cursor()
        try:
            cur.execute(
                "UPDATE item SET " +
                ", ".join(
                    x +
                    "=:" +
                    x for x in keys) +
                " WHERE itemId = :itemId",
                item)
            self.db.commit()
        finally:
            cur.close()


class CatalogMixin:

    """ Provides the catalog, a directory like structure for finding items.
        The user can choose the path were applications find items they
        understand. """

    # allowed names of items in the catalog
    ITEM_NAME_RE = re.compile(r'[^/]+')

    ROOT_ITEM_SETTING_NAME = 'catalog.root.itemid'

    def __init__(self, cb):
        super().__init__(cb)
        self._rootItem = None

    def setRootId(self, rootId):
        """ Overwrite the id of the Root item, old is lost """

        r = self.getRootItem()
        if rootId == r.itemId:
            raise ValueError("Root Id already set to that value")
        if len(r) > 0:
            raise RuntimeError("Root item not Empty !")
        self._rootItem = None
        self.db.setSetting(self.ROOT_ITEM_SETTING_NAME, rootId)

    def _do_upgrade(self, v):
        super()._do_upgrade(v)
        if v < 1:
            self._rootItem = self.newItem(ITEM_TYPES.MAP)
            self._rootItem.save()
            i = self._rootItem.getItemId()
            self.db.setSetting(self.ROOT_ITEM_SETTING_NAME, i)

    def getRootItemId(self):
            return self.db.getSetting(self.ROOT_ITEM_SETTING_NAME)

    def getRootItem(self):
        self._selfCheck()
        if self._rootItem is None:
            i = self.db.getSetting(self.ROOT_ITEM_SETTING_NAME)
            self._rootItem = self.getItem(i)
        return self._rootItem

    def getItemByPath(self, path):
        itemId = self.getItemIdByPath(path)
        return self.getItem(itemId)

    def getItemIdByPath(self, path):
        """ return the id of an item from the catalog, even if that item is not
        yet locally available. """
        # No Loop detection neccessary as the path will have a finite length.
        if not len(path) > 0:
            raise ValueError("No Name specified")
        self._selfCheck()
        i = self.getRootItem().itemId
        logpath = []
        ids = set()
        for p in path:
            logpath.append(p)
            try:
                i = self.getItem(i).getId(p)
            except KeyError:
                raise
            except Exception as e:
                logger.error("Error during getByName at %r: %r:",
                             logpath, e)
                raise e
            else:
                if self.ITEM_NAME_RE.fullmatch(p) is None:
                    logger.warning("index contains invalid name: %s in %r",
                                   p, logpath[:-1])
        return i

    def putItemByPath(self, item, path, **kwargs):
        return self.putItemIdByPath(item.getItemId(), path, **kwargs)

    def putItemIdByPath(
            self,
            itemId,
            path,
            create_parents=False,
            overwrite_existing=False):
        """ Make an item id accessible by path in the catalog. The item does
        not have to be locally available. """
        # No loop detection needed since path has finite length.
        self._selfCheck()
        if not len(path) > 0:
            raise ValueError("No Name specified")
        if not conventions.isItemId(itemId):
            raise ValueError("Not an itemId: %s" % (itemId,))
        i = self.getRootItem()
        for p in path:
            m = self.ITEM_NAME_RE.fullmatch(p)
            if m is None:
                raise ValueError("Illegal name %s in %r" % (p, path))

        logpath = ['<root>']
        for p in path[:-1]:
            logpath.append(p)
            if p in i:
                i = i[p]
            elif create_parents:
                ni = self.newItem(ITEM_TYPES.MAP)
                i[p] = ni
                i.save()
                i = ni
            else:
                raise KeyError("Item %r has not Child %s" % (logpath[-2], p))

        p = path[-1]
        if not overwrite_existing:
            if p in i:
                raise ValueError("already exists: %r " % (path,))

        i.putId(p, itemId)
        i.save()

class IterationMixin():

    """ Provides Iterating Tools """

    def walkItemTree(self, item, callback, loopCB=None):
        """ Walk an item Tree.
            For every item, callback is called once if it has no children
            or once before and once after the child tree was walked.
            the callback gets passed the following named arguments:
                key - the key under which the items parent provided the itemId,
                        None for root
                itemId
                item - is null if the Item is not present
                down - True before the children are walked or there are no children
                up   - True after the children are walked or there are no children
                first- True for the virst child visited
                last - True for the last child visited
                ids  - the ids of the parent items
            The callback should return
                continue - Boolean wheather the child items should be walked

            loopCB can be a boolean whether to walk an item that is its own
            ancestor, or a calback that returns a boolean and gets gets passed
            the following named arguments:
                key, itemId, first, last

            The callback Arguments have the following properties:
                down == up == True for leave Items (with no children)
                down != up otherwise
                first == last == True for single Children
                level == len(ids)
                a stack from a clojure can be used by calling
                    stack.push() if `down` and stack.append() if `up`
        """
        def visit(key, itemId, first, last, ids):
            """ The function that recursively visits items """
            if itemId in ids:
                if isinstance(loopCB, bool):
                    if not loopCB:
                        return
                elif callable(loopCB):
                    r = loopCB(itemId=itemId, key=key, ids=ids, first=first,
                               last=last)
                    if r is None:
                        raise ValueError("Loop Callback must decide whether "
                                         "to step in the loop,return a bool",
                                         item, key, ids)
                    if not r:
                        return
                else:
                    raise ValueError("Loop detected", item, key, ids)

            idsWithSelf = ids + (itemId,)
            try:
                item = self.getItem(itemId)
            except KeyError:
                item = None
                it = iter(())
            else:
                try:
                    it = iter(item.childIdsWithKeys())
                except NotImplementedError:
                    it = iter(())

            try:
                k, i = next(it)
            except StopIteration:
                callback(key=key, itemId=itemId, item=item, down=True,
                         up=True, first=first, last=last, ids=ids)
            else:
                walk_children = callback(
                    key=key,
                    itemId=itemId,
                    item=item,
                    down=True,
                    up=False,
                    first=first,
                    last=last,
                    ids=ids)
                if walk_children is None or walk_children:
                    first = True
                    for nxt in it:
                        visit(k, i, first, False, idsWithSelf)
                        first = False
                        k, i = nxt
                    visit(k, i, first, True, idsWithSelf)

                callback(key=key, itemId=itemId, item=item, down=False,
                         up=True, first=first, last=last, ids=ids)

        # Allow passing item or itemId
        try:
            itemId = item.itemId
        except AttributeError:
            itemId = item

        visit(None, itemId, True, True, ())

    def iterateItemTree(self, item, notIterableCallback=None):
        """ yield every itemId in the tree once, even if item not local, avoid
        loops. If the item accessor does not implement the iterate functions,
        notIterableCallback is called which can raise an exception or do
        nothing"""
        def sub(path, itemId):
            yield itemId
            try:
                item = self.getItem(itemId)
            except KeyError:
                pass
            else:
                path = path + (itemId,)
                try:
                    children = item.childIds()
                except NotImplementedError:
                    # propably an undefined item Type
                    if callable(notIterableCallback):
                        notIterableCallback(path, item)
                    else:
                        raise
                else:
                    for id in children:
                        if id not in path:
                            yield from sub(path, id)
        try:
            itemId = item.getItemId()
        except AttributeError:
            itemId = item
        yield from sub((), itemId)
