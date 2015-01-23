import shutil
import tempfile
import pathlib
import unittest


from . import crypto
from . import utilcrypto

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))


class TestCryptoUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        t = pathlib.Path(tempfile.mkdtemp("TestCrypto"))
        cls.tempdir = t
        f = t / 'test.txt'
        with f.open('xt') as fh:
            fh.write("Foo Bar Baz")
        cls.testFile = f

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(str(cls.tempdir))

    def test_easyEncryption(self):
        b = b'Test Data'

        key = crypto.generateSymmetricEncryptionKey(128 // 8)

        e, iv = utilcrypto.encryptSymmetric(
            algorithm='aes-128-cbc-pkcs7pad', key=key, plainData=b)
        d = utilcrypto.decryptSymmetric(
            algorithm='aes-128-cbc-pkcs7pad', key=key, iv=iv, encryptedData=e)

        self.assertNotEqual(e, d)
        self.assertEqual(b, d)

    def test_passwordProtectAsymmetricKey(self):
        data = b'TestString Data'

        password = b'Password'
        algo = 'aes-128-cbc-pkcs7pad'
        pbkdf = 'pbkdf2-1k-hmac-sha1'

        pd = utilcrypto.passwordProtectData(data, password, algo, pbkdf)

        self.assertGreater(len(pd), len(data))
        self.assertEqual(-1, pd.find(data))

        ed = utilcrypto.extractPasswordProtectedData(pd, password)

        self.assertEqual(data, ed)

    def test_hashFile(self):
        """ verify crypto.hashFile """
        h = "cd19da525f20096a817197bf263f3fdbe6485f00ec7354b691171358ebb9f1a1"
        self.assertEqual(h, utilcrypto.hashFile('sha256', self.testFile))

    def test_fileHashEqual(self):
        """ verify crypto.fileHashEqual """
        h1 = "cd19da525f20096a817197bf263f3fdbe6485f00ec7354b691171358ebb9f1a1"
        h2 = "CD19DA525F20096A817197BF263F3FDBE6485F00EC7354B691171358EBB9F1A1"
        h3 = "Cd19Da525f20096A817197BF263f3fdbe6485f00EC7354B691171358EBb9f1a1"
        self.assertTrue(utilcrypto.fileHashEqual('sha256', self.testFile, h1))
        self.assertTrue(utilcrypto.fileHashEqual('sha256', self.testFile, h2))
        self.assertTrue(utilcrypto.fileHashEqual('sha256', self.testFile, h3))

    def test_hashString(self):
        self.assertEqual(
            utilcrypto.hashString(
                'sha256',
                'TestString'),
            '6dd79f2770a0bb38073b814a5ff000647b37be5abbde71ec9176c6ce0cb32a27')

    def test_authenticateMessage(self):
        m = utilcrypto.authenticateMessage(
            "hmac-sha1",
            b"key",
            b"The quick brown fox jumps over the lazy dog")
        self.assertEqual(m, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")

    def test_generatePassword(self):
        p1 = utilcrypto.generatePassword(10)
        p2 = utilcrypto.generatePassword(10)

        self.assertEqual(len(p1), 10)
        self.assertEqual(len(p2), 10)
        self.assertNotEqual(p1, p2)


class TestCipherSuites(unittest.TestCase):

    def test_has_some(self):
        self.assertIn('HASHEDRANDOM-sha256-WITH-aes-256-cbc-pkcs7pad',
                      utilcrypto.CIPHER_SUITES)
