""" Wrap pythons zlib Module """
import zlib

import s5.shared.compression


class CompressionFactory:

    class Compressor:

        def __init__(self, level):
            self.c = zlib.compressobj(level=level)
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
            self.d = zlib.decompressobj()
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
                raise RuntimeError("writing although finished")
            self.buff = self.buff + b

        def getDecompressed(self):
            if self._done:
                raise RuntimeError("reading from spent")
            if len(self.buff) > 0:
                try:
                    dec = self.d.decompress(self.buff)
                    self.buff = self.d.unconsumed_tail
                    return dec
                except zlib.error as e:
                    raise s5.compression.CompressionError("Zlib.error") from e
            if self._finished:
                self._done = True
                b = self.d.flush()
                if not self.d.eof:
                    raise ValueError("Bytes left after decompression")
                return b
            raise RuntimeError(
                "reading although buffer empty and not finished")

    def __init__(self, level):
        self.level = level

    def getDecompressor(self):
        return self.Decompressor()

    def getCompressor(self):
        return self.Compressor(self.level)


def Register(registry):
    provider = 'python-zlib'
    registry.registerCompressionAlgorithm(
        provider, 'zlib-0', CompressionFactory(0))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-1', CompressionFactory(1))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-2', CompressionFactory(2))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-3', CompressionFactory(3))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-4', CompressionFactory(4))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-5', CompressionFactory(5))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-6', CompressionFactory(6))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-7', CompressionFactory(7))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-8', CompressionFactory(8))
    registry.registerCompressionAlgorithm(
        provider, 'zlib-9', CompressionFactory(9))
