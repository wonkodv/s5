import random
import weakref
import logging
import shutil
import subprocess
import unittest
import unittest.mock
from unittest.mock import Mock
import io
import pathlib
import tempfile

from . import items
from ..shared.conventions import ITEM_TYPES

logger = logging.getLogger(__name__)


class ItemTestBase:

    class MemoryStorage:

        def __init__(self):
            self.buffer = b''
            self._exists = False
            self.sufx = None

        def open(self, mode, *args):
            if 'w' in mode:
                bio = io.BytesIO()
            else:
                assert self.exists
                bio = io.BytesIO(self.buffer)
            realclose = bio.close

            def dontClose():
                self.buffer = bio.getvalue()
                self._exists = True
                realclose()
            bio.close = dontClose
            return bio

        def with_suffix(self, x):
            if self.sufx is None:
                self.sufx = ItemTestBase.MemoryStorage()
            return self.sufx

        def replace(self, other):
            assert self._exists
            other.buffer = self.buffer
            other._exists = True
            self._exists = False

        def unlink(self):
            assert self._exists
            self.buffer = b''
            self._exists = False

        def exists(self):
            return self._exists

    def saveItem(self, it):
        fields = ("storage", "encryptionKey") + \
            items.PUBLIC_ITEM_METADATA_FIELDS
        self.itemData[it.itemId] = dict([(k, getattr(it, k)) for k in fields])
        self.itemData[it.itemId]['saver'] = it.saver  # avoid double weakrefing

    def setUp(self):
        self.i = 1
        self.itemData = {}

    def newItem(self, typ):
        self.i = self.i + 1
        data = dict(
            itemId="%032X" % self.i,
            contentType=typ,
            storage=self.MemoryStorage(),
            saver=self,
            hashMethod='sha256',
            encryptionMethod='aes-128-cbc-pkcs7pad',
            compressionMethod='zlib-9'
        )
        it = items.makeNewItem(**data)
        self.saveItem(it._wrapped)
        return it

    def getItem(self, i):
        return items.makeOldItem(**self.itemData[i])

    def genTestItem(self, content):
        itm = self.newItem(ITEM_TYPES.JSON)
        itm.setContent(content)
        itm.save()
        return itm


class TestTheTestRig(ItemTestBase, unittest.TestCase):

    def test_seperateClients(self):
        ms = ItemTestBase.MemoryStorage()
        with ms.open('wb') as f:
            f.write(b'test')
            f.write(b'testtest')

        self.assertEqual(b'testtesttest', ms.buffer)

        with ms.open('rb') as f:
            c = f.read()
        self.assertEqual(b'testtesttest', c)

        with ms.open('wb') as f:
            f.write(b'X')

        self.assertEqual(b'X', ms.buffer)

        with ms.open('rb') as f:
            c = f.read()
        self.assertEqual(b'X', c)


class TestItem(ItemTestBase, unittest.TestCase):

    def test_item(self):
        i = self.newItem('undefined')
        # no content yet:
        with self.assertRaises(RuntimeError):
            i.getContentBytes()
        c = i.getContentDef(b'42')
        self.assertEqual(c, b'42')
        # no content yet:
        with self.assertRaises(RuntimeError):
            i.save()
        i.saveNewContent(b'36')
        c = i.getContentDef(b'42')
        self.assertEqual(c, b'36')

        i = self.newItem('undefined')
        i = self.getItem(i.itemId)
        with self.assertRaises(RuntimeError):
            i.getContentBytes()

    def test_ItemWrapped(self):
        """ assure that Item-internals are hidden """
        i = self.newItem('undefined')
        with self.assertRaises(AttributeError):
            i.itemId = 12

    def test_modTime(self):
        i = self.newItem('undefined')
        self.assertIsNone(i.getLastModified())
        i.saveNewContent(b'36')
        lm = i.getLastModified()
        self.assertIsNotNone(lm)
        i.saveNewContent(b'42')
        lm2 = i.getLastModified()
        self.assertGreater(lm2, lm)
        i.saveWithModTime(lm)
        lm2 = i.getLastModified()
        self.assertEqual(lm2, lm)


class TestItemCryptography(ItemTestBase, unittest.TestCase):

    def test_encryption(self):
        """ Test if dec(enc(x)) == x """
        i = self.newItem('undefinedType')
        i.saveNewContent(b'TestString')
        id = i.itemId

        i = self.getItem(id)

        c = i.getContentBytes()
        self.assertEqual(b'TestString', c)
        c = i.getContentBytes()
        self.assertEqual(b'TestString', c)

        i.saveNewContent(b'TestTwentyBlocks' * 20 + b'plus half')
        id = i.itemId
        c = i.getContentBytes()
        self.assertEqual(b'TestTwentyBlocks' * 20 + b'plus half', c)

    def test_largeBinaryData(self):
        """ Detect a crypto bug that happend with data > 9 kb """

        b = (b'.' * 1023 + b'|') * 9
        i = self.newItem('urn:x-s5:file')
        i.updateCompressionMethod('null')
        i.updateEncryptionMethod('null')
        i.saveFromBlocks([b])  # 2 MB

        c = i._wrapped.storage.buffer

        # storing works
        self.assertEqual(b'Encrypted(Compressed[' + b + b'])', c)

        id = i.itemId

        i = self.getItem(id)

        c = i.getContentBytes()

    def test_encryptionIV(self):
        """ Test that IVs are not reused """

        i = self.newItem('undefinedType')
        i.saveNewContent(b'TestString')
        c1 = i._wrapped.storage.buffer
        h1 = i._wrapped.encryptedContentHash
        i.saveNewContent(b'TestString')
        c2 = i._wrapped.storage.buffer
        h2 = i._wrapped.encryptedContentHash
        self.assertNotEqual(c1, c2)
        self.assertNotEqual(h1, h2)

    def test_encryptionKeyChange(self):
        """ test if changed key is used """
        i = self.newItem('undefinedType')
        data = b'TestTwentyBlocks' * 20 + b'plus half'
        i.saveNewContent(data)

        c1 = i._wrapped.storage.buffer
        h1 = i.getContentHash()
        k1 = i._wrapped.encryptionKey

        i.saveNewContent(data)

        c2 = i._wrapped.storage.buffer
        h2 = i.getContentHash()
        k2 = i._wrapped.encryptionKey
        cont = i.getContentBytes()

        self.assertEqual(cont, data)
        self.assertEqual(h1, h2)

        self.assertNotEqual(c1, c2)
        self.assertNotEqual(k1, k2)

    def test_encryptionAlgorithmChange(self):
        """ test if changedAlgorithm is used """
        i = self.newItem('undefinedType')

        data = b'TestTwentyBlocks' * 20 + b'plus half'

        i.saveNewContent(data)

        c1 = i._wrapped.storage.buffer

        h1 = i.getContentHash()
        i.updateEncryptionMethod('cast-128-cbc-pkcs7pad')
        cont = i.getContentBytes()
        self.assertEqual(cont, data)

        it = i.getContentIterator()

        a = list(it)

        i.save()

        c2 = i._wrapped.storage.buffer
        h2 = i.getContentHash()
        cont = i.getContentBytes()
        self.assertEqual(cont, data)
        self.assertEqual(h1, h2)
        self.assertNotEqual(c1, c2)

    def test_saveAbortedAfterMetaSave(self):
        """ Test recovery from aborted Save befor MetaData was saved """
        i = self.newItem('undefinedType')

        data = b'TestTwentyBlocks' * 20 + b'plus half'

        i.saveNewContent(data)

        tmp = i._wrapped.storage.with_suffix('.temp')
        sto = i._wrapped.storage
        itemId = i.itemId
        del i

        # abort after metadata was stored but before .temp file replaced the real file
        # the old file contains data that decrypts badly

        # append block that decrypts to garbage so the first blocks look good
        with tmp.open('wb') as ftmp, sto.open('rb') as fsto:
            ftmp.write(fsto.read())
        with tmp.open('rb') as ftmp, sto.open('wb') as fsto:
            fsto.write(ftmp.read())
            fsto.write(b'\x10' * 16)

        self.assertTrue(tmp.exists())

        with self.assertLogs(items.__name__, "INFO") as cm:
            i = self.getItem(itemId)

        self.assertRegex(cm.output[0], ".*file was recovered")

        # tmp.replace(sto) -> sto exists, tmp not
        self.assertFalse(tmp.exists())

        self.assertEqual(data, i.getContentBytes())

    def test_saveAbortedBeforeMetaSave(self):
        """ Test recovery from aborted Save befor MetaData was saved """
        i = self.newItem('undefinedType')

        data = b'TestTwentyBlocks' * 20 + b'plus half'

        i.saveNewContent(data)

        tmp = i._wrapped.storage.with_suffix('.temp')
        sto = i._wrapped.storage
        itemId = i.itemId
        del i

        # abort before metadata was stored
        # the newly written tmp file contains
        # unreadble stuff

        # append block that decrypts to garbage so the first blocks look good
        with tmp.open('wb') as f1, sto.open('rb') as f0:
            f1.write(f0.read())
            f1.write(b'\x10' * 16)

        self.assertTrue(tmp.exists())

        with self.assertLogs(items.__name__, "WARNING") as cm:
            i = self.getItem(itemId)

        self.assertRegex(cm.output[0], ".*could not be read")

        self.assertFalse(tmp.exists())

        self.assertEqual(data, i.getContentBytes())

    def test_compressionMethodChange(self):
        i = self.newItem('undefinedType')

        data = b'TestTwentyBlocks' * 20 + b'plus half'

        i.saveNewContent(data)
        h1 = i.getContentHash()
        i.updateCompressionMethod('zlib-9')
        cont = i.getContentBytes()
        self.assertEqual(cont, data)

        it = i.getContentIterator()

        a = list(it)

        i.save()
        h2 = i.getContentHash()
        cont = i.getContentBytes()
        self.assertEqual(cont, data)
        self.assertEqual(h1, h2)

    def test_hashing(self):
        i = self.newItem('undefinedType')
        self.assertIsNone(i.getContentHash())
        i.saveNewContent(
            b'TestString  with all bytes ' + bytes(x for x in range(0, 256)))
        self.assertEqual(i.getContentHash(
        ), 'c931ed31b184feb7a04e15ed5daa593ec6365fe5d48a8069c5ce3b1021cc275a')

        i.saveNewContent(b'TestString')
        self.assertEqual(i.getContentHash(
        ), '6dd79f2770a0bb38073b814a5ff000647b37be5abbde71ec9176c6ce0cb32a27')

        i.updateHashMethod('sha256')
        i.save()
        self.assertEqual(i.getContentHash(
        ), '6dd79f2770a0bb38073b814a5ff000647b37be5abbde71ec9176c6ce0cb32a27')

        i.updateHashMethod('sha512')
        self.assertEqual(i.getContentHash(
        ), '6dd79f2770a0bb38073b814a5ff000647b37be5abbde71ec9176c6ce0cb32a27')
        i.save()
        self.assertEqual(
            i.getContentHash(),
            '69dfd91314578f7f329939a7ea6be4497e6fe3909b9c8f308fe711d29d4340d90d77b7fdf359b7d0dbeed940665274f7ca514cd067895fdf59de0cf142b62336')


class TestJSONItem(ItemTestBase, unittest.TestCase):

    def test_jsonitem(self):
        """ Test Json Content Methods, and when they are saved """
        i = self.newItem(ITEM_TYPES.JSON)
        c = i.getContent()
        self.assertIsNone(c)

        i.setContent([])
        c = i.getContent()

        l0 = i.getLastModified()
        self.assertIsNone(l0)

        i.save()

        l1 = i.getLastModified()
        c.append(123456)
        l2 = i.getLastModified()
        # item does not know about its content getting changed
        self.assertEqual(l1, l2)
        i.save()
        l3 = i.getLastModified()
        self.assertEqual(l2, l3)  # save does not change anything therefore

        i.touchContent()

        i.save()

        l4 = i.getLastModified()

        # after touchContent, JsonItem knows the content changed
        self.assertLess(l3, l4)

    def test_warnsLostDataAtFree(self):
        i = self.newItem(ITEM_TYPES.JSON)
        i.setContent("SavedData")
        i.save()
        i.setContent("LostData")

        with self.assertWarns(UserWarning):
            del i

    def test_warnsNotWhenDefaultDataiLost(self):
        # wont fail but raise a warning
        i = self.newItem(ITEM_TYPES.JSON)
        i.getContent()
        del i


class TestCollectionItem(ItemTestBase, unittest.TestCase):

    def test_collection(self):
        ic = self.newItem(ITEM_TYPES.LIST)
        ic.append(self.genTestItem(0))
        ic.append(self.genTestItem(1))
        ic.append(self.genTestItem(2))
        ic.append(self.genTestItem(3))
        ic.save()

        itemId = ic.itemId

        i = self.getItem(itemId)
        self.assertEqual(3, i[3].getContent())

    def test_listMethods(self):
        ic = self.newItem(ITEM_TYPES.LIST)
        ic.append(self.genTestItem(0))
        ic.append(self.genTestItem(1))
        ic.append(self.genTestItem(2))
        ic.append(self.genTestItem(3))
        ic.save()

        x = []
        for i in ic:
            x.append(i.getContent())

        self.assertEqual(x, list(range(4)))
        self.assertEqual(len(ic), 4)

        del(ic[2])

        self.assertEqual([i.getContent() for i in ic], [0, 1, 3])

        ic[2] = self.genTestItem(4)

        self.assertEqual([i.getContent() for i in ic], [0, 1, 4])

        ic.save()  # avoid warning


class TestMapItem(ItemTestBase, unittest.TestCase):

    def test_map(self):
        ic = self.newItem(ITEM_TYPES.MAP)
        ic['stringkey'] = self.genTestItem(0)
        with self.assertRaises(TypeError):
            ic[True] = self.genTestItem(1)
        with self.assertRaises(TypeError):
            ic[25] = self.genTestItem(2)
        with self.assertRaises(TypeError):
            ic[None] = self.genTestItem(3)
        ic.save()

        itemId = ic.itemId

        self.assertEqual(0, self.getItem(itemId)['stringkey'].getContent())

    def test_mapMethods(self):
        ic = self.newItem(ITEM_TYPES.MAP)
        ic['a'] = self.genTestItem(0)
        ic['b'] = self.genTestItem(1)
        ic['c'] = self.genTestItem(2)
        ic['d'] = self.genTestItem(3)

        self.assertIn('a', ic.keys())
        self.assertIn('b', ic.keys())
        self.assertIn('c', ic.keys())
        self.assertIn('d', ic.keys())

        testDict = {}
        for k, v in ic.items():
            testDict[k] = v.getContent()

        self.assertEqual(testDict, {'a': 0, 'b': 1, 'c': 2, 'd': 3})
        self.assertEqual(4, len(ic))

        self.assertIn('c', ic)
        del(ic['c'])
        self.assertNotIn('c', ic)

        ic.save()  # avoid warning


class TestFileItem(ItemTestBase, unittest.TestCase):

    def test_FileItem(self):
        i = self.newItem(ITEM_TYPES.FILE + '(text/plain)')

        self.assertEqual(i.mimeType, 'text/plain')
        i.saveNewContent("Latin1 Chars: üäö".encode("latin-1"))
        itemId = i.itemId

        item = self.getItem(itemId)
        with self.assertRaises(UnicodeDecodeError):
            item.getContentBytes().decode('utf8')

    def test_noMimeType(self):
        i = self.newItem(ITEM_TYPES.FILE)
        self.assertIsNone(i.mimeType)

    def test_StreamSupport(self):
        b = b'Lorem Ipsum dolor sit amet ' + bytes(range(0, 256))

        t = pathlib.Path(tempfile.mkdtemp("TestFileItem"))
        p = t / 'Source.txt'
        with p.open('wb') as f:
            f.write(b * 100)

        i = self.newItem(ITEM_TYPES.FILE + '(text/plain)')

        i.saveFromPath(p)

        h1 = i.getContentHash()
        h2 = subprocess.check_output(['sha256sum', str(p)]).decode(
            'utf-8').partition(' ')[0]
        self.assertEqual(h1, h2)

        id = i.itemId

        i = self.getItem(id)

        self.assertEqual(i.getContentBytes(), b * 100)

        p2 = t / 'Target.txt'
        i.loadIntoPath(p2)

        h2 = subprocess.check_output(['diff', str(p), str(p2)])

        shutil.rmtree(str(t))

    def test_StrRepr(self):
        i = self.newItem(ITEM_TYPES.FILE)
        s = str(i)
        r = repr(i)
        logger.debug("String: %s Repr: %s", s, r)
