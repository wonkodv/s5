"""
    Implements the Item class to encrypt and store data.
    Implements the Accessor mechanism. Accessors wrap an item, exposing mos
    properties (readonly) and some methods to read and modify content.
    Different Accessors handle items of different kinds.
    Accessors are imlemented by plugins in s5/plugins/items/
"""

from ..shared import serialize
import logging
import io
import collections.abc
import datetime
import json
import os.path
import pathlib
import sqlite3

from ..shared import utilcrypto
from ..shared import crypto
from ..shared import compression
from ..shared.conventions import ITEM_TYPES
from ..plugins.items import Accessors


def getAccessorForItem(item):
    t = item.decryptedContentType
    try:
        cls = Accessors.getAccessorForType(t)
        return cls(item)
    except KeyError:
        return BaseAccessor(item)


def makeNewItem(**kwargs):
    """ Make a new Item"""
    i = Item()
    i.initNew(**kwargs)
    a = getAccessorForItem(i)
    return a


def makeOldItem(**kwargs):
    """ Make an item that existed previously """
    i = Item()
    i.initOld(**kwargs)
    a = getAccessorForItem(i)
    return a


def makeOldItemWithoutWrap(**kwargs):
    """ Make an old item, and return it unwrapped """
    i = Item()
    i.initOld(**kwargs)
    return i


# All fields of an item that contain encrypted or not secret data
PUBLIC_ITEM_METADATA_FIELDS = (
    "itemId",
    "lastModified",
    "hashMethod",
    "encryptionMethod",
    "compressionMethod",
    "sizeOfEncryptedContent",
    "contentEncryptionIV",
    "encryptedContentType",
    "typeEncryptionIV",
    "hashEncryptionIV",
    "encryptedContentHash",
)


class Item:

    """ Handle the encryption, compression, loading and saving of data """

    def initOld(self,
                itemId,
                storage,
                saver,
                lastModified,

                encryptionMethod,
                encryptionKey,
                hashMethod,
                compressionMethod,

                sizeOfEncryptedContent,

                contentEncryptionIV,

                encryptedContentHash,
                hashEncryptionIV,

                encryptedContentType,
                typeEncryptionIV
                ):

        self.itemId = itemId
        self.storage = storage
        self.saver = saver

        self.compressionMethod = compressionMethod

        self.hashMethod = hashMethod
        self.encryptedContentHash = encryptedContentHash
        assert lastModified is None or \
            isinstance(lastModified, datetime.datetime),\
            "lastModified should be date, not %s (%s)" % (
                type(lastModified).__name__, str(lastModified)
            )
        self.lastModified = lastModified

        self.sizeOfEncryptedContent = sizeOfEncryptedContent

        self.oldHashMethod = self.hashMethod

        self.encryptionMethod = encryptionMethod
        self.encryptionKey = encryptionKey
        self.contentEncryptionIV = contentEncryptionIV
        self.hashEncryptionIV = hashEncryptionIV
        self.typeEncryptionIV = typeEncryptionIV

        self.oldCompressionMethod = self.compressionMethod
        self.oldEncryptionMethod = self.encryptionMethod
        self.oldEncryptionKey = self.encryptionKey
        self.oldContentEncryptionIV = self.contentEncryptionIV
        self.oldHashEncryptionIV = self.hashEncryptionIV
        self.oldTypeEncryptionIV = self.typeEncryptionIV

        self.encryptedContentType = encryptedContentType

        b = utilcrypto.decryptSymmetric(
            algorithm=self.encryptionMethod,
            key=self.encryptionKey,
            iv=self.typeEncryptionIV,
            encryptedData=encryptedContentType)
        self.decryptedContentType = b.decode('utf-8')

        if encryptedContentHash is not None:
            b = utilcrypto.decryptSymmetric(
                algorithm=self.encryptionMethod,
                key=self.encryptionKey,
                iv=self.hashEncryptionIV,
                encryptedData=encryptedContentHash)
            self.decryptedContentHash = b.decode('utf-8')
        else:
            self.decryptedContentHash = None

        self.needsReEncryption = False
        self.needsReHashing = False

        self.contentIsUndefined = lastModified is None

        if not self.contentIsUndefined:
            tmp = self.storage.with_suffix(".temp")
            if tmp.exists():
                try:
                    # go through content, if no Error is raised, the encryption
                    # params and ContentHash are OK
                    for x in self.getContentIterator(tmp):
                        pass
                except(compression.CompressionError, crypto.DecryptionError, ValueError):
                    # Compression, Decryption or the ContentHashing Test failed
                    logging.getLogger(__name__).warning(
                        ".temp file was found but could not be read")
                    tmp.unlink()
                else:
                    tmp.replace(self.storage)
                    logging.getLogger(__name__).info(
                        "updated .temp file was recovered")

    def initNew(self,
                itemId,
                storage,
                saver,
                hashMethod,
                contentType,
                compressionMethod,
                encryptionMethod
                ):
        self.itemId = itemId
        self.storage = storage
        self.saver = saver

        self.hashMethod = hashMethod
        self.encryptionMethod = encryptionMethod
        self.compressionMethod = compressionMethod

        self.sizeOfEncryptedContent = None

        self.lastModified = None

        encFact = crypto.getSymmetricEncryptionAlgorithm(encryptionMethod)
        self.encryptionKey = crypto.generateSymmetricEncryptionKey(
            encFact.getKeySize())

        self.contentEncryptionIV = None

        self.decryptedContentHash = None
        self.encryptedContentHash = None
        self.hashEncryptionIV = None

        self.decryptedContentType = contentType

        b, iv = utilcrypto.encryptSymmetric(
            algorithm=self.encryptionMethod,
            key=self.encryptionKey,
            plainData=contentType.encode('utf-8')
        )
        self.typeEncryptionIV = iv
        self.encryptedContentType = b

        # used to test if reencrypting ContentType is neccessary
        self.oldEncryptionMethod = encryptionMethod

        self.contentIsUndefined = True

    def updateHashMethod(self, newHashMethod):
        self.hashMethod = newHashMethod
        self.needsReHashing = True

    def updateEncryptionMethod(self, newEncryptionAlgorithm):
        self.encryptionMethod = newEncryptionAlgorithm
        self.needsReEncryption = True

    def updateCompressionMethod(self, newCompressionMethod):
        self.compressionMethod = newCompressionMethod
        self.needsReEncryption = True

    def save(self):
        """ Save the Item only if content or crypto changed
        return boolean if changed"""

        if not self.hasContent():
            raise RuntimeError('item has no content yet')

        if self.needsReEncryption:
            i = self.getContentIterator()
            self.saveFromBlocks(i)
            return True
        elif self.needsReHashing:
            h = crypto.getHashAlgorithm(self.hashMethod)
            for chunck in self.getContentIterator():
                h.update(chunck)
            self.decryptedContentHash = h.hexdigest()
            b, iv = utilcrypto.encryptSymmetric(
                algorithm=self.encryptionMethod,
                key=self.encryptionKey,
                plainData=serialize.strToBytes(self.decryptedContentHash)
            )
            self.encryptedContentHash = b
            self.hashEncryptionIV = iv
            self.needsReHashing = False
            self.saver.saveItem(self)
            return True
        else:
            return False  # nothing changed, nothing was saved

    def saveWithModTime(self, modTime):
        self.lastModified = modTime
        if not self.save():  # save if anything besides LM changed
            self.saver.saveItem(self)  # save only metadata to db

    def saveFromBlocks(self, blocks):
        """
            The byte sequences are taken from blocks, concatenated, compressed,
            encrypted and stored.
            By storing the data in a temporary file, then saving the metadata
            and replcaing the content file with the temporary one, this
            operation can be interrupted without creating a corrupt item.
        """

        self.lastModified = datetime.datetime.now()

        encryptorFactory = crypto.getSymmetricEncryptionAlgorithm(
            self.encryptionMethod)
        self.contentEncryptionIV = encryptorFactory.getIV()


        # Generate a new item Key on every save action.
        self.encryptionKey = crypto.generateSymmetricEncryptionKey(
            encryptorFactory.getKeySize())

        encryptor = encryptorFactory.getEncryptor(
            self.encryptionKey, self.contentEncryptionIV)

        compressorFactory = compression.getCompressionAlgorithm(
            self.compressionMethod)
        compressor = compressorFactory.getCompressor()

        hasher = crypto.getHashAlgorithm(self.hashMethod)

        s = self.storage.with_suffix(".temp")

        size = 0

        with s.open('wb') as f:
            for plainTextChunck in blocks:
                hasher.update(plainTextChunck)
                compressor.putPlain(plainTextChunck)
                while compressor.hasMore():
                    compressedChunck = compressor.getCompressed()
                    encryptor.putPlain(compressedChunck)
                    while encryptor.hasMore():
                        encryptedChunck = encryptor.getEncrypted()
                        f.write(encryptedChunck)
                        size = size + len(encryptedChunck)
            compressor.finish()
            while compressor.hasMore():
                compressedChunck = compressor.getCompressed()
                encryptor.putPlain(compressedChunck)
                # can not be much, is already in ram, leave in encryptors
                # buffers
            encryptor.finish()
            while encryptor.hasMore():
                encryptedChunck = encryptor.getEncrypted()
                f.write(encryptedChunck)
                size = size + len(encryptedChunck)

        self.sizeOfEncryptedContent = size

        #   store the contentHash de- and encrypted
        self.decryptedContentHash = hasher.hexdigest()
        b, iv = utilcrypto.encryptSymmetric(
            algorithm=self.encryptionMethod,
            key=self.encryptionKey,
            plainData=serialize.strToBytes(self.decryptedContentHash)
        )
        self.encryptedContentHash = b
        self.hashEncryptionIV = iv

        # reencrypt contenttype
        b, iv = utilcrypto.encryptSymmetric(
            algorithm=self.encryptionMethod,
            key=self.encryptionKey,
            plainData=serialize.strToBytes(self.decryptedContentType)
        )
        self.encryptedContentType = b
        self.typeEncryptionIV = iv

        # Store Metadata in db
        self.saver.saveItem(self)

        # replace the old file with the temporary after if metadata was stored
        # successfully
        s.replace(self.storage)

        self.oldCompressionMethod = self.compressionMethod
        self.oldHashMethod = self.hashMethod
        self.oldEncryptionMethod = self.encryptionMethod
        self.oldEncryptionKey = self.encryptionKey
        self.oldContentEncryptionIV = self.contentEncryptionIV
        self.oldHashEncryptionIV = self.hashEncryptionIV
        self.oldTypeEncryptionIV = self.typeEncryptionIV

        self.contentIsUndefined = False

        self.needsReEncryption = False
        self.needsReHashing = False

    def getContentIterator(self, storage=None):
        """
            get the stored content, decrypt it, decompress it and return it as
            iterator of chuncks of arbitrary size
        """
        if not self.hasContent():
            raise RuntimeError('item has no content yet')
        encryptorFactory = crypto.getSymmetricEncryptionAlgorithm(
            self.oldEncryptionMethod)
        decryptor = encryptorFactory.getDecryptor(
            self.oldEncryptionKey, self.oldContentEncryptionIV)

        compressorFactory = compression.getCompressionAlgorithm(
            self.oldCompressionMethod)
        decompressor = compressorFactory.getDecompressor()

        hasher = crypto.getHashAlgorithm(self.oldHashMethod)

        if storage is None:
            storage = self.storage

        with storage.open('rb') as f:
            encryptedChunck = True
            while encryptedChunck:
                encryptedChunck = f.read(io.DEFAULT_BUFFER_SIZE)
                decryptor.putEncrypted(encryptedChunck)
                while decryptor.hasMore():
                    compressedChunck = decryptor.getDecrypted()
                    decompressor.putCompressed(compressedChunck)
                    while decompressor.hasMore():
                        plainTextChunck = decompressor.getDecompressed()
                        hasher.update(plainTextChunck)
                        yield plainTextChunck
        decryptor.finish()
        while decryptor.hasMore():
            compressedChunck = decryptor.getDecrypted()
            decompressor.putCompressed(compressedChunck)
            # leave it in decompressor's buffer, it was in decryptors buffer
            # before
        decompressor.finish()
        while decompressor.hasMore():
            plainTextChunck = decompressor.getDecompressed()
            hasher.update(plainTextChunck)
            yield plainTextChunck

        if not hasher.hexdigest() == self.decryptedContentHash:
            raise ValueError("Item storage was corrupted")

    def getEncryptedContentIter(self):
        if not self.hasContent():
            raise RuntimeError('item has no content yet')
        with self.storage.open('rb') as f:
            r = f.read(io.DEFAULT_BUFFER_SIZE)
            while len(r) > 0:
                yield r
                r = f.read(io.DEFAULT_BUFFER_SIZE)

    def getEncryptedMetaData(self):
        """ Return the metadata, only the public fields and the encrypted ones. """
        return dict((k, getattr(self, k)) for k in PUBLIC_ITEM_METADATA_FIELDS)

    def getItemId(self):
        return self.itemId

    def getContentType(self):
        return self.decryptedContentType

    def getContentHash(self):
        return self.decryptedContentHash

    def getHashMethod(self):
        return self.hashMethod

    def hasContent(self):
        return not self.contentIsUndefined

    def getItemSaver(self):
        """ The object that has getItem(itemId) and save(item) """
        return self.saver

    def getLastModified(self):
        return self.lastModified

    def getSizeOfEncryptedContent(self):
        return self.sizeOfEncryptedContent


class BaseAccessor:

    """ Accessors wrap an item, to offer methods to access the items content.
        They should subclass this and be implemented in
        s5.plugin.items.*

        Items that cache the content must discard that cache at endUpdate(),
        possibly warn about lost changes.

    """

    def __init__(self, item):
        self._wrapped = item

    def beginUpdate(self):
        self._wrapped = None

    def endUpdate(self, item):
        self._wrapped = item

    # Item attributes that accessors expose read only
    ITEM_ACCESSIBLE_ATTRIBUTES = PUBLIC_ITEM_METADATA_FIELDS + (
        "getEncryptedMetaData",
        "getEncryptedContentIter",
        "getContentHash",
        "getContentIterator",
        "getContentType",
        "getItemId",
        "getItemSaver",
        "getLastModified",
        "getHashMethod",
        "hasContent",
        "saveWithModTime",
        "saveFromBlocks",
        "updateEncryptionMethod",
        "updateEncryptionKey",
        "updateHashMethod",
        "updateCompressionMethod",
    )

    def __getattr__(self, attr):
        if attr in self.ITEM_ACCESSIBLE_ATTRIBUTES:
            return getattr(self._wrapped, attr)
        raise AttributeError(
            "'%s' object has no attribute '%s' ", type(self), attr)

    def __setattr__(self, attr, value):
        if attr in self.ITEM_ACCESSIBLE_ATTRIBUTES:
            raise AttributeError("Read only Attribute")
        else:
            self.__dict__[attr] = value

    def getContentBytes(self):
        return b''.join(self.getContentIterator())

    def getContentDef(self, default=None):
        if self._wrapped.hasContent():
            return self.getContentBytes()
        return default

    def save(self):
        """ make changes persistent  (e.g. after changing the encryption method)"""
        self._wrapped.save()

    def saveFromStream(self, stream, bufferSize=io.DEFAULT_BUFFER_SIZE):
        """ read the content of a file-like object, store it in item and save
        the changes."""
        def readBlock():
            b = True
            while b:
                b = stream.read(bufferSize)
                yield b

        self.saveFromBlocks(readBlock())

    def saveNewContent(self, newContent):
        """ set the item content to `newContent` and save """
        self.saveFromBlocks([newContent])

    def childIds(self):
        """ return iterable of itemIds for sync and garbage collection """
        raise NotImplementedError()

    def childIdsWithKeys(self):
        """ return iterable of Tuples of (key,itemId) for debugging"""
        raise NotImplementedError()

    def __repr__(self):
        t = type(self).__name__
        ct = self.getContentType()
        id = self.getItemId()
        lm = self.getLastModified()
        ch = self.getContentHash()
        return '<%s,%s,%s,%s,%s>' % (t, id, ct, lm, ch)

    def __str__(self):
        return "%s/%s" % (self.getItemId()[:10], self.getContentType())
