"""
    Test all cryptographic algorithms, provided by s5.plugins.crypto.*
"""


import shutil
import tempfile
import unittest
import logging
import pathlib
import random


from ..plugins.crypto import Algorithms
from . import crypto

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))


class TestCrypto(unittest.TestCase):

    """ Tests the crypto Module

    Hash functions are tested by comparison to precalculated values

    Symmetric Encryption functions are tested by comparison with precalculated
    Values and by decrypting and verifying aginst original value

    Asymmetric encryption Functions contain a random element and are only
    tested by encrypting and decrypting values. Also the size of generated keys
    is tested.

    Random Functions are tested by checking upper boundary of Number and
    testing if it is larger than a 20 bit smaller number. this can fail
    in about 1 in a million test runs.
    """

    def test_getRandomItemIdentifier(self):
        """ verify crypto.getRandomItemIdentifier returning valid identifiers """
        i1 = crypto.getRandomItemIdentifier()
        i2 = crypto.getRandomItemIdentifier()
        self.assertNotEqual(i1, i2)
        self.assertTrue(int(i1, 16) > 1 << 108)
        self.assertTrue(int(i1, 16) < 1 << 128)

    def test_getRandomBits(self):
        k1 = crypto.getRandomBits(128)
        k2 = crypto.getRandomBits(128)
        self.assertNotEqual(k1, k2)
        self.assertTrue(k1 > 1 << 108)
        self.assertTrue(k1 < 1 << 128)

    def test_getRandomInt(self):
        x = [3, 4, 5, 6, 7]
        for i in range(1000):
            r = crypto.getRandomInt(3, 7)
            if r in x:
                x.remove(r)
            if x == []:
                break
        self.assertEqual(x, [])

    def test_encryption(self):
        f = crypto.getSymmetricEncryptionAlgorithm('aes-128-cbc-pkcs7pad')

        key = crypto.generateSymmetricEncryptionKey(128 // 8)
        iv = f.getIV()

        encryptor = f.getEncryptor(key, iv)

        encryptor.putPlain(b'first Field')
        encryptor.finish()
        firstField = b''
        while encryptor.hasMore():
            firstField = firstField + encryptor.getEncrypted()

        encryptor.continueUsing()

        encryptor.putPlain(b'2nd Field')
        encryptor.finish()
        secondField = b''
        while encryptor.hasMore():
            secondField = encryptor.getEncrypted()

        decryptor = f.getDecryptor(key, iv)

        decryptor.putEncrypted(firstField)
        decryptor.finish()
        firstDecr = b''
        while decryptor.hasMore():
            firstDecr = firstDecr + decryptor.getDecrypted()

        decryptor.continueUsing()

        decryptor.putEncrypted(secondField)
        decryptor.finish()
        secondDecr = b''
        while decryptor.hasMore():
            secondDecr = secondDecr + decryptor.getDecrypted()

        self.assertEqual(b'first Field', firstDecr)
        self.assertEqual(b'2nd Field', secondDecr)

    def test_predictedPaddingLength(self):
        f = crypto.getSymmetricEncryptionAlgorithm('aes-128-cbc-pkcs7pad')
        key = crypto.generateSymmetricEncryptionKey(128 // 8)
        iv = f.getIV()
        encryptor = f.getEncryptor(key, iv)

        self.assertEqual(encryptor.getSizeAfterEncryption(17), 32)
        self.assertEqual(encryptor.getSizeAfterEncryption(31), 32)
        self.assertEqual(encryptor.getSizeAfterEncryption(16), 32)
        self.assertEqual(encryptor.getSizeAfterEncryption(15), 16)

    def test_generateSymmetricEncryptionKey(self):
        k1 = crypto.generateSymmetricEncryptionKey(128 // 8)
        k2 = crypto.generateSymmetricEncryptionKey(128 // 8)

        self.assertNotEqual(k1, k2)

        self.assertEqual(len(k1), 128 // 8)
        self.assertEqual(len(k2), 128 // 8)

    def test_asymetricEncryption(self):

        algo = 'rsa-1024-OAEP-SHA1'
        a = crypto.getAsymmetricEncryptionAlgorithm(algo)

        priv = a.generatePrivateKey()
        pub = a.getPublicFromPrivate(priv)

        self.assertEqual(priv['type'], 'private')
        self.assertEqual(pub['type'], 'public')

        self.assertIn(pub['modulus'], range(1 << 1000, 1 << 1024))

        # badly implemented, the eading 0 bytes might be stripped, not by oaep
        b = b'\x00\x00TestBytes'

        enc = a.getEncryptor(pub)
        ct = enc.encrypt(b)

        dec = a.getDecryptor(priv)
        pt = dec.decrypt(ct)

        self.assertEqual(b, pt)

    def test_mac(self):
        """ Test hmac against values from wikipedia: """

        def comp(alg, pw, msg):
            mac = crypto.getMACAlgorithm(alg)
            mac = mac(pw)
            mac.update(msg)
            return mac.hexdigest()

        self.assertEqual(comp('hmac-sha1', b'', b''),
                         "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
        self.assertEqual(comp('hmac-sha1', b'key',
                              b'The quick brown fox jumps over the lazy dog'),
                         "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")

        self.assertEqual(
            comp(
                'hmac-sha256',
                b'',
                b''),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")
        self.assertEqual(
            comp(
                'hmac-sha256',
                b'key',
                b'The quick brown fox jumps over the lazy dog'),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")


class TestProviders(unittest.TestCase):

    def test_random_providers(self):
        """ Test every Random Provider  """
        a = [0, 2 ** 128 - 1]
        for provider, rng in Algorithms.random_algorithms.items():
            n = rng.getrandbits(1)
            self.assertIn(n, [0, 1])

            n = rng.getrandbits(128)
            self.assertTrue(n > 1 << 108)
            self.assertTrue(n < 1 << 128)

            for i in range(1, 100):
                n = rng.getrandbits(128)
                self.assertNotIn(n, a)
                a.append(n)

            rng.getrandbits(4096)

    def test_hash_providers(self):
        """ Test every Hash Provider  """
        testBytes = 'TestString'.encode('utf-8')
        expected = {
            'sha1': 'd598b03bee8866ae03b54cb6912efdfef107fd6d',
            'sha224': 'cf374400f337b98aec8277d533010f54727c6628d63c2c4299e72fbe',
            'sha384': 'c0a59eced4822f065701ec5abc51531c948864ae84391ec68' +
            'e80c135d2f3fe50923445e9b436dfa2afdaa7cefa8367bb',
            'sha256': '6dd79f2770a0bb38073b814a5ff000647b37be5abbde71ec9' +
            '176c6ce0cb32a27',
            'sha512': '69dfd91314578f7f329939a7ea6be4497e6fe3909b9c8f308' +
            'fe711d29d4340d90d77b7fdf359b7d0dbeed940665274f7ca514cd' +
            '067895fdf59de0cf142b62336',
            'whirlpool': '0326823736b5b8f6762edccda2f38af120a802db77aab1' +
            '772c2cb1d22877950c415cebbfd2ce2fd8ff937807fd8de0fe951d' +
            '68ecc25458f71692517b954a3ab5',
            'ripemd160': 'bdfbb9e0f55ae303a977082b30aa7c18b454032e'}
        for algo, provider in Algorithms.hashAlgos.iterateAlgoProviders():
            if algo not in expected:
                logging.getLogger(__name__).info(
                    'result for algorithm not tested: %s', algo)
            else:
                h = Algorithms.getHashAlgorithm(algo, provider)
                h.update(testBytes)
                d = h.hexdigest()
                self.assertEqual(
                    d, expected[algo], '%s/%s hashes wrong' % (provider, algo))

    def test_symmetricEncryption_providers(self):
        """ Test every Encryption Provider

        Verified by encrypting `testInput` and comparing results with output
        of openssl:
            $ testString="..."
            $ key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
            $ iv=000102030405060708090a0b0c0d0e0f
            $ echo -n "$testString" | openssl enc -aes-128-cbc -K "$key" -iv "$iv" | xxd
         """
        testInput = 'Bytes to test encryption and decryption with a total length of 71 Bytes'.encode(
            'utf-8')
        testValues = {'aes-128-cbc-pkcs7pad': """
                        4eef 8abb 2381 b39e b606 cb61 1551 9294
                        5517 4f67 ac0b d59f 8038 13e1 eb4d d76c
                        8375 434f 20f6 f113 a3ce 246c a3fc 3d9a
                        6cec 34a1 d947 7c74 78a4 c984 9222 d9ca
                        690a 75ee 0c03 99f3 3d3a d063 54f2 3366
                    """,
                      'aes-192-cbc-pkcs7pad': """
                        2be9 c40d d3c9 34ec cde5 1878 3bb5 a676
                        7689 fc4b 5f8a ed80 ca4a 2ce5 ae13 7ec6
                        648b 202d d366 b664 f8c3 c23b f27d 6775
                        c450 c681 6362 5d61 6a1c 3286 4b0c 74e5
                        42bb 4349 d4e0 c6b2 c5b6 d4cd 2817 4dd3
                    """,
                      'aes-256-cbc-pkcs7pad': """
                        0fe3 31ed 6d1a f9b3 fa1e 487a 978f 71b4
                        6dd4 be88 d693 37f7 2bbf 589d fdcf b097
                        8fc1 c887 f45d 0454 e28d f819 02c1 f98f
                        2621 656e 25d5 cd46 440e 7f19 961f 614b
                        9e14 4f64 cd36 7a71 a588 f601 fa72 296b
                    """,
                      'cast-128-cbc-pkcs7pad': """
                        2b91 bde0 8451 0845 f6a8 5705 f1af e17c
                        73b1 17af 55ac 216f 0563 178f c2a6 0667
                        5fad fe8f 04b1 8b5e 0f3a 174a 1743 b2f6
                        3cd1 89fb a511 e63f bb9d b531 9901 951e
                        f523 3029 fcf3 2637
                    """,
                      'null': """
                        456e 6372 7970 7465 6428 4279 7465 7320
                        746f 2074 6573 7420 656e 6372 7970 7469
                        6f6e 2061 6e64 2064 6563 7279 7074 696f
                        6e20 7769 7468 2061 2074 6f74 616c 206c
                        656e 6774 6820 6f66 2037 3120 4279 7465
                        7329
                    """
                      }

        def getSequentialBytes(num):
            return bytes([x & 0xFF for x in range(num)])
        commonSymmetricKey = getSequentialBytes(500)
        commonIV = bytes(bytearray.fromhex("000102030405060708090a0b0c0d0e0f"))

        for algo, provider in Algorithms.symmetricEncryptionAlgos.iterateAlgoProviders(
        ):
            if algo not in testValues:
                logging.getLogger(__name__).info(
                    'result for algorithm not tested: %s', algo)
            else:
                factory = Algorithms.getSymmetricEncryptionAlgorithm(
                    algo, provider)

                iv = commonIV[:factory.getIvSize()]
                key = commonSymmetricKey[:factory.getKeySize()]

                enc = factory.getEncryptor(key, iv)

                enc.putPlain(testInput)
                enc.finish()

                ct = b''
                while enc.hasMore():
                    ct = ct + enc.getEncrypted()

                expected = testValues[algo]
                expected = bytearray.fromhex(expected.replace('\n', ' '))

                self.assertEqual(
                    ct, expected, 'encryption %s/%s encrypts wrong' %
                    (provider, algo))

                dec = factory.getDecryptor(key, iv)

                pt = b''
                dec.putEncrypted(ct)
                dec.finish()
                while dec.hasMore():
                    pt = pt + dec.getDecrypted()

                self.assertEqual(testInput, pt)

                encryptor = factory.getEncryptor(key, iv)

                encryptor.putPlain(b'first Field')
                encryptor.finish()
                firstFieldEncrypted = b''
                while encryptor.hasMore():
                    firstFieldEncrypted = firstFieldEncrypted + \
                        encryptor.getEncrypted()

                encryptor.continueUsing()

                encryptor.putPlain(b'2nd Field')
                encryptor.finish()
                secondFieldEncrypted = b''
                while encryptor.hasMore():
                    secondFieldEncrypted = secondFieldEncrypted + \
                        encryptor.getEncrypted()

                decryptor = factory.getDecryptor(key, iv)

                decryptor.putEncrypted(firstFieldEncrypted)
                decryptor.finish()
                firstDecr = b''
                while decryptor.hasMore():
                    firstDecr = firstDecr + decryptor.getDecrypted()

                decryptor.continueUsing()

                decryptor.putEncrypted(secondFieldEncrypted)
                decryptor.finish()
                secondDecr = b''
                while decryptor.hasMore():
                    secondDecr = secondDecr + decryptor.getDecrypted()

                self.assertEqual(b'first Field', firstDecr)
                self.assertEqual(b'2nd Field', secondDecr)

                iv = factory.getIV()
                key = crypto.generateSymmetricEncryptionKey(
                    factory.getKeySize())
                b = b'Test String'

                encryptor = factory.getEncryptor(key, iv)
                encryptor.putPlain(b)
                encryptor.finish()
                ct = b''
                while encryptor.hasMore():
                    ct = ct + encryptor.getEncrypted()

                decryptor = factory.getDecryptor(key, iv)
                decryptor.putEncrypted(ct)
                decryptor.finish()
                pt = b''
                while decryptor.hasMore():
                    pt = pt + decryptor.getDecrypted()

                self.assertEqual(pt, b)

    def test_asymmetricEncryption_providers(self):
        tests = [
            {
                'algo': 'rsa-1024-oaep-sha1',
                'field': 'modulus',
                'upper bound': 1024,
                'lower bound': 1000,
            },
            {
                'algo':'rsa-2048-oaep-sha256',
                'field':'modulus',
                'upper bound': 2048,
                'lower bound': 2020,
            } ,
            {
                'algo':'rsa-4096-oaep-sha256',
                'field':'modulus',
                'upper bound': 4096,
                'lower bound': 4070,
            }
        ]
        for test in tests:

            a = crypto.getAsymmetricEncryptionAlgorithm(test['algo'])

            priv = a.generatePrivateKey()
            pub = a.getPublicFromPrivate(priv)

            self.assertEqual(priv['type'], 'private')
            self.assertEqual(pub['type'], 'public')

            self.assertGreater(pub[test['field']], 1 << test['lower bound'])
            self.assertLess(pub[test['field']], 1 << test['upper bound'])

            b = b'\x00\x00TestBytes'

            enc = a.getEncryptor(pub)
            ct = enc.encrypt(b)

            dec = a.getDecryptor(priv)
            pt = dec.decrypt(ct)

            self.assertEqual(b, pt, " %s encrypts Wrong" % test['algo'])

    def test_pbkdf_providers(self):
        pas = b"Secret"
        salt1 = b"Salt"
        salt2 = b"Pepper"

        for algo, provider in Algorithms.pbkdfAlgos.iterateAlgoProviders():
            if int(algo.split('-')[1].replace('k', '000')) > 1000:
                continue
            f = Algorithms.getPBKDFAlgorithm(algo, provider)
            k1 = f(pas, salt1, 16)
            k2 = f(pas, salt2, 16)
            self.assertEqual(len(k1), 16)
            self.assertNotEqual(k1, k2)

    def test_mac_providers(self):
        message = b"Message"
        passwd1 = b"Pass1"
        passwd2 = b"Pass2"

        for algo, provider in Algorithms.macAlgos.iterateAlgoProviders():
            fact = Algorithms.getMACAlgorithm(algo, provider)

            mac1 = fact(passwd1)
            mac1.update(message)
            mac1 = mac1.hexdigest()

            mac11 = fact(passwd1, message).hexdigest()

            self.assertEqual(mac1, mac11)

            mac2 = fact(passwd2, message).hexdigest()

            self.assertNotEqual(mac1, mac2)
