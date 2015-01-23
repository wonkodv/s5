""" A compression algortihm that does nothing for testing """
import s5.shared.compression


class CompressionFactory:

    class Compressor:

        def __init__(self):
            self.buff = b'Compressed['
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

            if self.buff:
                chunck = self.buff
                self.buff = b''
                return chunck

            if self._finished:
                self._done = True
                b = self.buff + b']'
                self.buff = b''
                return b

            raise RuntimeError(
                "reading although buffer empty and not finished")

    class Decompressor:

        def __init__(self):
            self.buff = b''
            self._done = False
            self._finished = False
            self._skip = len(b'Compressed[')
            self._skipped = b''

        def finish(self):
            self._finished = True

        def hasMore(self):
            if self._finished:
                return not self._done
            return len(self.buff) > 1

        def putCompressed(self, b):
            if self._finished:
                raise RuntimeError("writing although finished")
            self.buff = self.buff + b

        def getDecompressed(self):
            if self._done:
                raise RuntimeError("reading from spent")
            if self._skip > 0:
                b = self.buff[:self._skip]
                self.buff = self.buff[self._skip:]
                self._skip = self._skip - len(b)
                self._skipped = self._skipped + b
            else:
                assert self._skipped == b'Compressed['

            if len(self.buff) > 1:
                chunck = self.buff[:-1]
                self.buff = self.buff[-1:]
                return chunck

            if self._finished:
                self._done = True
                b = self.buff[:-1]
                assert self.buff[-1:] == b']', "%r != ']'" % self.buff[-1:]
                self.buff = b''
                return b
            raise RuntimeError(
                "reading although buffer empty and not finished")

    def __init__(self):
        pass

    def getDecompressor(self):
        return self.Decompressor()

    def getCompressor(self):
        return self.Compressor()


def Register(registry):
    provider = 'null'
    registry.registerCompressionAlgorithm(
        provider, 'null', CompressionFactory())
