""" implements a symmetric Encryption Algorithm that does nothing, for testing
"""
import warnings
import s5.shared.crypto


class SymmetricEncryptorFactory:

    class SymmetricEncryptor:

        def __init__(self):
            self.buff = b'Encrypted('
            self._finished = False
            self._done = False

        def putPlain(self, b):
            if self._finished:
                raise RuntimeError("writing to encryptor although finished")
            self.buff = self.buff + b

        def finish(self):
            self._finished = True

        def hasMore(self):
            if self._finished:
                return not self._done
            return len(self.buff) >= 1

        def getEncrypted(self):
            if self._done:
                raise RuntimeError("reading from spent")

            if self.buff:
                chunck = self.buff
                self.buff = b''
                return chunck

            if self._finished:
                self._done = True
                b = self.buff + b')'
                self.buff = b''
                return b

            raise RuntimeError(
                "reading although buffer empty and not finished")

        def continueUsing(self):
            assert self._done
            assert self.buff == b''
            self._done = False
            self._finished = False
            self.buff = b'Encrypted('

    class SymmetricDecryptor:

        def __init__(self):
            self.buff = b''
            self._finished = False
            self._done = False
            self._skip = len(b'Encrypted(')
            self._skipped = b''

        def finish(self):
            self._finished = True

        def putEncrypted(self, b):
            if self._finished:
                raise RuntimeError("writing although finished")
            self.buff = self.buff + b

        def hasMore(self):
            if self._finished:
                return not self._done
            return len(self.buff) >= 2  # last byte is )

        def getDecrypted(self):
            if self._done:
                raise RuntimeError("reading from spent")

            if self._skip > 0:
                b = self.buff[:self._skip]
                self.buff = self.buff[self._skip:]
                self._skip = self._skip - len(b)
                self._skipped = self._skipped + b
            else:
                assert self._skipped == b'Encrypted('

            if len(self.buff) > 1:
                chunck = self.buff[:-1]
                self.buff = self.buff[-1:]
                return chunck

            if self._finished:
                self._done = True
                b = self.buff[:-1]
                assert self.buff[-1:] == b')', "%r != ')'" % self.buff[-1:]
                self.buff = b''
                return b
            raise RuntimeError(
                "reading although buffer empty and not finished")

        def continueUsing(self):
            assert self._done
            assert self.buff == b''
            self._done = False
            self._finished = False
            self._skip = len(b'Encrypted(')
            self._skipped = b''

    def getBlockSize(self):
        return 1

    def getIV(self):
        return s5.shared.crypto.getRandomBytes(self.getIvSize())

    def getIvSize(self):
        return 1

    def getKeySize(self):
        return 10

    def getEncryptor(self, key, iv=None):
        warnings.warn("NULL-Encryption is used")
        return SymmetricEncryptorFactory.SymmetricEncryptor()

    def getDecryptor(self, key, iv=None):
        return SymmetricEncryptorFactory.SymmetricDecryptor()


def Register(registry):
    provider = "null"

    registry.registerSymmetricEncryptionAlgorithm(
        provider, 'null', SymmetricEncryptorFactory())
