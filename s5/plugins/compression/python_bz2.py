""" Wrap pythons bz2 Module """
import bz2

import s5.shared.compression


class CompressionFactory:

    class Compressor:

        def __init__(self, level):
            self.c = bz2.BZ2Compressor(level)
            self.buff = b''
            self._done = False
            self._finished = False

        def finish(self):
            self._finished = True

        def hasMore(self):
            if self._finished:
                return not self._done
            return len(self.buff) > 0

        def putPlain(self, b):
            if self._finished:
                raise RuntimeError("writing although finished")
            self.buff = self.buff + b

        def getCompressed(self):
            if self._done:
                raise RuntimeError("reading from spent")
            if len(self.buff) > 0:
                r = self.c.compress(self.buff)
                self.buff = b''
                return r
            if self._finished:
                self._done = True
                return self.c.flush()
            raise RuntimeError(
                "reading although buffer empty and not finished")

    class Decompressor:

        def __init__(self):
            self.d = bz2.BZ2Decompressor()
            self.buff = b''
            self._done = False
            self._finished = False

        def finish(self):
            self._finished = True

        def hasMore(self):
            if self._finished:
                return not self._done
            return len(self.buff) > 0

        def putCompressed(self, b):
            if self._finished:
                raise RuntimeError("Putting Data into finished")
            self.buff = self.buff + b

        def getDecompressed(self):
            if self._done:
                raise RuntimeError("reading from spent")
            if len(self.buff) > 0:
                try:
                    dec = self.d.decompress(self.buff)
                except OSError:
                    raise s5.compression.CompressionError("bz2 error")
                self.buff = b''
                return dec
            if self._finished:
                if not self._done:
                    self._done = True
                    return b''
                raise RuntimeError("reading although spent")
            raise RuntimeError("reading although buffer empty")

    def __init__(self, level):
        self.level = level

    def getDecompressor(self):
        return self.Decompressor()

    def getCompressor(self):
        return self.Compressor(self.level)


def Register(registry):
    provider = 'python-bz2'
    registry.registerCompressionAlgorithm(
        provider, 'bz2-1', CompressionFactory(1))
    registry.registerCompressionAlgorithm(
        provider, 'bz2-2', CompressionFactory(2))
    registry.registerCompressionAlgorithm(
        provider, 'bz2-3', CompressionFactory(3))
    registry.registerCompressionAlgorithm(
        provider, 'bz2-4', CompressionFactory(4))
    registry.registerCompressionAlgorithm(
        provider, 'bz2-5', CompressionFactory(5))
    registry.registerCompressionAlgorithm(
        provider, 'bz2-6', CompressionFactory(6))
    registry.registerCompressionAlgorithm(
        provider, 'bz2-7', CompressionFactory(7))
    registry.registerCompressionAlgorithm(
        provider, 'bz2-8', CompressionFactory(8))
    registry.registerCompressionAlgorithm(
        provider, 'bz2-9', CompressionFactory(9))
