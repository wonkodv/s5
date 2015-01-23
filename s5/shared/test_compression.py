import shutil
import tempfile
import pathlib
import unittest

from ..plugins.compression import Algorithms
from . import compression

TEMP_DIRECTORY = pathlib.Path(tempfile.mkdtemp("Test" + __name__))


def setUpModule():
    assert TEMP_DIRECTORY.exists()
    assert list(TEMP_DIRECTORY.iterdir()) == []


def tearDownModule():
    shutil.rmtree(str(TEMP_DIRECTORY))


class TestCompression(unittest.TestCase):

    def test_defaultWorks(self):
        b = b'Test' + b'0' * 1020

        f = compression.getCompressionAlgorithm('bz2-9')
        c = f.getCompressor()
        c.putPlain(b)
        c.finish()
        x = b''
        while c.hasMore():
            x = x + c.getCompressed()

        d = f.getDecompressor()
        d.putCompressed(x)
        d.finish()
        x = b''
        while d.hasMore():
            x = x + d.getDecompressed()

        self.assertEqual(x, b)

    def test_smallCompression(self):
        testBytes = b'Byte sequence to test compression and decompression that has a total length of 87 Bytes'
        for algo, provider in Algorithms.compressionAlgorithms.iterateAlgoProviders(
        ):
            fact = Algorithms.getCompressionAlgorithm(algo, provider)
            compressor = fact.getCompressor()

            compressor.putPlain(testBytes)
            compressor.finish()
            comped = b''
            while compressor.hasMore():
                comped = comped + compressor.getCompressed()

            # short strings compressed can become longer
            self.assertNotEqual(len(comped), len(testBytes))
            decompressor = fact.getDecompressor()

            decompressor.putCompressed(comped)
            decompressor.finish()
            decomped = b''

            while decompressor.hasMore():
                decomped = decomped + decompressor.getDecompressed()

            self.assertEqual(testBytes, decomped)

    def test_largeCompression(self):
        t = TEMP_DIRECTORY / 'TestLargeCompreesion'
        t.mkdir()

        pClear = t / 'clear'
        pComp = t / 'comp'
        pDecomp = t / 'decomp'

        with pClear.open('wb') as f:
            f.write(b'\x00' * 1024 * 1024)
            f.write(b'Test' * 1024 * 1024)

        plaintextsize = 5 * 1024 * 1024
        bs = 4 * 1024
        self.assertEqual(plaintextsize, pClear.stat().st_size)

        for algo, provider in Algorithms.compressionAlgorithms.iterateAlgoProviders(
        ):
            if algo in ('zlib-9', 'bz2-9'):  # limit on good algorithms
                fact = Algorithms.getCompressionAlgorithm(algo, provider)
                compressor = fact.getCompressor()

                with pComp.open('wb') as fc:
                    with pClear.open('rb') as fp:
                        plain = fp.read(bs)
                        while len(plain) > 0:
                            compressor.putPlain(plain)
                            while compressor.hasMore():
                                fc.write(compressor.getCompressed())
                            plain = fp.read(bs)
                    compressor.finish()
                    while compressor.hasMore():
                        fc.write(compressor.getCompressed())

                # it should be easy to compress
                self.assertLess(pComp.stat().st_size, plaintextsize // 100)

                decompressor = fact.getDecompressor()

                with pDecomp.open('wb') as fd:
                    with pComp.open('rb') as fc:
                        comped = fc.read(bs)
                        while len(comped) > 0:
                            decompressor.putCompressed(comped)
                            while decompressor.hasMore():
                                fd.write(decompressor.getDecompressed())
                            comped = fc.read(bs)
                    decompressor.finish()
                    while decompressor.hasMore():
                        fd.write(decompressor.getDecompressed())
