from ..shared import utilcrypto
import pathlib
import shutil
import tempfile
import unittest
from . import callbacks

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))



class TestDefaultConfig(unittest.TestCase):
    def test_ciphersuites(self):
        cb = callbacks.ConfigCallbacks(TEMP_DIRECTORY)
        for s in cb.getConnectionCipherSuites():
            self.assertIn(s, utilcrypto.CIPHER_SUITES)

    def test_veersioningScheme(self):
        with (TEMP_DIRECTORY / 'config.ini').open('wt') as f:
            f.write('[Server TestServer]\nVersioning Scheme = TestScheme')
        cb = callbacks.ConfigCallbacks(TEMP_DIRECTORY)

        v = cb.getNewSyncVersioningScheme(None,'Server1')
        assert v == 'last(10)'
        v = cb.getNewSyncVersioningScheme(None,'TestServer')
        assert v == 'TestScheme'

