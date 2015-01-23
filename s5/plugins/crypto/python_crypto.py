""" Adapter between the pycrypto package (Crypto)
    <https://www.dlitz.net/software/pycrypto/api/2.6/>
    and the S5-Plugin API """

try:
    import Crypto
    import Crypto.Cipher.AES
    import Crypto.Cipher.CAST
    import Crypto.Cipher.PKCS1_OAEP
    import Crypto.Cipher.blockalgo
    import Crypto.Hash
    import Crypto.Hash.RIPEMD
    import Crypto.Hash.SHA
    import Crypto.Hash.SHA224
    import Crypto.Hash.SHA256
    import Crypto.Hash.SHA384
    import Crypto.Hash.SHA512
    import Crypto.Hash.HMAC
    import Crypto.Protocol.KDF
    import Crypto.PublicKey.RSA
    import Crypto.Random
    import Crypto.Random.random
    import Crypto.Util.number
except ImportError as e:
    from .. import PluginDependencyMissing
    raise PluginDependencyMissing('pycrypto') from e

import s5.shared.crypto as crypto


HASH_ALGORITHMS = {
    'sha1': Crypto.Hash.SHA,
    'sha224': Crypto.Hash.SHA224,
    'sha256': Crypto.Hash.SHA256,
    'sha384': Crypto.Hash.SHA384,
    'sha512': Crypto.Hash.SHA512,
    'RIPEMD160': Crypto.Hash.RIPEMD
}


class SymmetricEncryptorFactory:

    class SymmetricEncryptor:

        def __init__(self, cipher):
            self.cipher = cipher
            self.buff = b''
            self._finished = False
            self._done = False

        def putPlain(self, b):
            if self._finished:
                raise RuntimeError("writing although finished")
            self.buff = self.buff + b

        def finish(self):
            self._finished = True

        def hasMore(self):
            if self._finished:
                return not self._done
            bs = self.cipher.block_size
            return len(self.buff) >= bs

        def getEncrypted(self):
            if self._done:
                raise RuntimeError("reading from spent")
            bs = self.cipher.block_size
            blocks = len(self.buff) // bs
            if blocks > 0:
                idx = bs * blocks
                chunck = self.buff[:idx]
                self.buff = self.buff[idx:]
                return self.cipher.encrypt(chunck)

            if self._finished:
                self._done = True
                b = self.buff
                self.buff = b''
                return self.cipher.encrypt(self.pad(b))

            raise RuntimeError(
                "reading although buffer empty and not finished")

        def continueUsing(self):
            assert self._done
            self._done = False
            self._finished = False

        def getSizeAfterEncryption(self, size):
            bs = self.cipher.block_size
            x = bs - (size % bs)
            size = size + x
            assert size % bs == 0
            return size

        def pad(self, m):
            """
            pad m with bytes so the message has a length of n * blockSize
            by appending x bytes containg x where x >= 1 and x<= blockSize
            """
            bs = self.cipher.block_size
            l = len(m)
            x = bs - (l % bs)
            # 16 - ( 16 % 16) =16
            # 16 - ( 15 % 16) =1
            # 16 - ( 1 % 16) =15

            p = bytes((x,) * x)

            return m + p

    class SymmetricDecryptor:

        def __init__(self, cipher):
            self.cipher = cipher
            self.buff = b''
            self._finished = False
            self._done = False

        def finish(self):
            self._finished = True

        def putEncrypted(self, b):
            if self._finished:
                raise RuntimeError("writing although finished")
            self.buff = self.buff + b

        def hasMore(self):
            if self._finished:
                return not self._done
            bs = self.cipher.block_size
            return len(self.buff) >= 2 * bs  # last block can contain padding

        def getDecrypted(self):
            if self._done:
                raise RuntimeError("reading from spent")
            bs = self.cipher.block_size
            blocks = len(self.buff) // bs
            blocks = blocks - 1  # the last block can contain padding
            if blocks > 0:
                idx = bs * blocks
                chunck = self.buff[:idx]
                self.buff = self.buff[idx:]
                return self.cipher.decrypt(chunck)

            if self._finished:
                self._done = True
                b = self.buff
                self.buff = b''
                return self.unpad(self.cipher.decrypt(b))

            raise RuntimeError(
                "reading although buffer empty and not finished")

        def continueUsing(self):
            assert self._done
            self._done = False
            self._finished = False

        def unpad(self, m):
            if len(m) == 0:
                raise crypto.DecryptionError(
                    "Not a correctly PKCS7-Padded Message: Size=0")
            if len(m) % self.cipher.block_size != 0:
                raise crypto.DecryptionError(
                    "Not a correctly PKCS7-Padded Message, %d not multiple of %d",
                    len(m),
                    self.cipher.block_size)

            x = m[-1]
            for b in m[-x:]:
                if b != x:
                    raise crypto.DecryptionError(
                        "Not a correctly PKCS7-Padded Message: %02X != %02X",
                        b, x)
            return m[:-x]

    def __init__(self, algorithm, mode, keysize):
        self.algorithm = algorithm
        self.mode = mode
        self.keySize = keysize

    def getBlockSize(self):
        return self.algorithm.block_size

    def getIV(self):
        s = self.getIvSize()
        if s is not None:
            return crypto.getRandomBytes(s)
        return None

    def getIvSize(self):
        if self.mode == Crypto.Cipher.blockalgo.MODE_CBC:
            return self.algorithm.block_size
        raise NotImplementedError("Cipher Mode not supported: %d", self.mode)

    def getKeySize(self):
        return self.keySize

    def _params(self, key, iv):
        assert len(key) == self.keySize, 'Key must have Size %d but has %d' % (
            self.keySize, len(key))
        key = bytes(key)

        s = self.getIvSize()
        if s is not None:
            iv = bytes(iv)
            assert len(iv) == self.getIvSize(), 'IV must have Size %d but has %d' % (
                self.getIvSize(), len(iv))
        return key, iv

    def getEncryptor(self, key, iv=None):
        key, iv = self._params(key, iv)
        c = self.algorithm.new(key, self.mode, iv)
        return SymmetricEncryptorFactory.SymmetricEncryptor(c)

    def getDecryptor(self, key, iv=None):
        key, iv = self._params(key, iv)
        c = self.algorithm.new(key, self.mode, iv)
        return SymmetricEncryptorFactory.SymmetricDecryptor(c)


class RSAAlgorithm:

    class AsymmetricEncryptor():

        def __init__(self, key, hashAlgo):
            self.oaep = Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher(
                key=key,
                hashAlgo=hashAlgo,
                mgfunc=None,
                label=None)

        def encrypt(self, cipherText):
            return self.oaep.encrypt(cipherText)

    class AsymmetricDecryptor():

        def __init__(self, key, hashAlgo):
            self.oaep = Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher(
                key=key,
                hashAlgo=hashAlgo,
                mgfunc=None,
                label=None)

        def decrypt(self, cipherText):
            try:
                return self.oaep.decrypt(cipherText)
            except ValueError as e:
                raise crypto.DecryptionError(str(e))

    def __init__(self, keyBits, hashAlgo):
        self.keyBits = keyBits
        self.name = 'rsa-%d-OAEP-%s' % (keyBits, hashAlgo)
        self.hashAlgo = HASH_ALGORITHMS[hashAlgo]

    def generatePrivateKey(self):
        """ Generate a key for the selected Algorithm, return as dictionary """
        priv = Crypto.PublicKey.RSA.generate(
            self.keyBits, crypto.getRandomBytes)
        privData = {
            'algorithm': self.name,
            'type': 'private',
            'modulus': priv.n,
            'public exponent': priv.e,
            'private exponent': priv.d,
        }
        return privData

    def getPublicFromPrivate(self, privkey):
        priv = Crypto.PublicKey.RSA.construct(
            (privkey['modulus'],
             privkey['public exponent'],
             privkey['private exponent']))
        pub = priv.publickey()
        pubData = {
            'algorithm': self.name,
            'type': 'public',
            'modulus': pub.n,
            'public exponent': pub.e,
        }
        return pubData

    def getDecryptor(self, privkey):
        assert privkey['algorithm'].startswith('rsa-')
        assert privkey['type'] == 'private'
        priv = Crypto.PublicKey.RSA.construct(
            (privkey['modulus'],
             privkey['public exponent'],
             privkey['private exponent']))
        return self.AsymmetricDecryptor(priv, self.hashAlgo)

    def getEncryptor(self, pubkey):
        assert pubkey['algorithm'].startswith('rsa-')
        assert pubkey['type'] == 'public'
        pub = Crypto.PublicKey.RSA.construct(
            (pubkey['modulus'], pubkey['public exponent']))
        return self.AsymmetricEncryptor(pub, self.hashAlgo)


def HMACFactory(hashMod):
    def new(key, msg=None):
        return Crypto.Hash.HMAC.new(key, msg, hashMod)
    return new


def PBKDFFactory(iterations, prf):
    def pbkdf(password, salt, size):
        return Crypto.Protocol.KDF.PBKDF2(password, salt, size, iterations)
    return pbkdf


def Register(registry):
    provider = "pycrypto"

    # CSPRNG
    registry.registerRandomNumberGenerator(
        provider, Crypto.Random.random.StrongRandom())

    # Symmetric Encryption
    registry.registerSymmetricEncryptionAlgorithm(
        provider,
        'aes-256-cbc-pkcs7pad',
        SymmetricEncryptorFactory(
            Crypto.Cipher.AES,
            Crypto.Cipher.AES.MODE_CBC,
            256 // 8))
    registry.registerSymmetricEncryptionAlgorithm(
        provider,
        'aes-192-cbc-pkcs7pad',
        SymmetricEncryptorFactory(
            Crypto.Cipher.AES,
            Crypto.Cipher.AES.MODE_CBC,
            192 // 8))
    registry.registerSymmetricEncryptionAlgorithm(
        provider,
        'aes-128-cbc-pkcs7pad',
        SymmetricEncryptorFactory(
            Crypto.Cipher.AES,
            Crypto.Cipher.AES.MODE_CBC,
            128 // 8))
    registry.registerSymmetricEncryptionAlgorithm(
        provider,
        'cast-128-cbc-pkcs7pad',
        SymmetricEncryptorFactory(
            Crypto.Cipher.CAST,
            Crypto.Cipher.CAST.MODE_CBC,
            128 // 8))

    # Asymmetric Encryption
    combinations = []
    for i in 1024, 2048, 4096, 8192, 16384:
        for hashAlgo in HASH_ALGORITHMS:
            rsa = RSAAlgorithm(i, hashAlgo)
            registry.registerAsymmetricEncryptionAlgorithm(
                provider, rsa.name, rsa)

    for name, mod in HASH_ALGORITHMS.items():
        # plain hash
        registry.registerHashAlgorithm(provider, name, mod.new)

        # HMAC
        mac = HMACFactory(mod)
        registry.registerMAC(provider, "hmac-" + name, mac)

        # PBKDF
        for i in 1, 10, 100, 1000:
            registry.registerPBKDF(
                provider,
                'pbkdf2-%dk-hmac-%s' % (i, name),
                PBKDFFactory( i* 1024, mac))
