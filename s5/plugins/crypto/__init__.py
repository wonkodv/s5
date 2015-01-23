"""
    The registry for cryptographic algorithms
"""


import pathlib

from .. import BaseRegistry
from .. import AlgorithmProviderStore


class CryptoAlgorithmRegistry(BaseRegistry):

    """
        # preferred_hash_provider['sha256']='hashlib'
        # preferred_hash_provider['sha3-256']='pycrypto'
    """

    def __init__(self, path, package):
        super().__init__(path, package)
        self.random_algorithms = {}
        self.preferred_random_provider = None

        self.hashAlgos = AlgorithmProviderStore()
        self.symmetricEncryptionAlgos = AlgorithmProviderStore()
        self.asymmetricEncryptionAlgos = AlgorithmProviderStore()
        self.pbkdfAlgos = AlgorithmProviderStore()
        self.macAlgos = AlgorithmProviderStore()

    def registerRandomNumberGenerator(self, provider, impl):
        """ register a function similar to getrandbits(num) """
        assert callable(impl.getrandbits)
        assert callable(impl.randint)
        provider = provider.lower()
        self.random_algorithms[provider] = impl
        if self.preferred_random_provider is None:
            self.preferred_random_provider = provider

    def getRandomNumberGenerator(self):
        self.ensureLoaded()
        return self.random_algorithms[self.preferred_random_provider]

    def setProviderForRandomNumberGenerator(self, provider):
        provider = provider.lower()
        if provider in self.random_algorithms[provider]:
            self.preferred_random_provider = provider
        else:
            raise KeyError("no provider %s" % provider)

    def registerHashAlgorithm(self, provider, algo, factory):
        """ register a function that returns new hashers similar to hashlib.new(algo) """
        assert callable(factory)
        self.hashAlgos.add(provider, algo, factory)

    def getHashAlgorithm(self, algo, provider=None):
        self.ensureLoaded()
        return self.hashAlgos.get(algo, provider)()

    def setProviderForHashAlgo(self, algo, provider):
        self.hashAlgos.setProviderForAlgorithm(algo, provider)

    def registerSymmetricEncryptionAlgorithm(self, provider, algo, factory):
        """ register a factory that returns new encrypters and decrypters"""
        assert callable(factory.getDecryptor)
        assert callable(factory.getEncryptor)
        self.symmetricEncryptionAlgos.add(provider, algo, factory)

    def getSymmetricEncryptionAlgorithm(self, algo, provider=None):
        self.ensureLoaded()
        return self.symmetricEncryptionAlgos.get(algo, provider)

    def setProviderForSymmetricEncryptionAlgo(self, algo, provider):
        self.symmetricEncryptionAlgos.setProviderForAlgorithm(algo, provider)

    def registerAsymmetricEncryptionAlgorithm(self, provider, algo, factory):
        """ register a factory that returns new encrypters and decrypters"""
        assert callable(factory.getDecryptor)
        assert callable(factory.getEncryptor)
        self.asymmetricEncryptionAlgos.add(provider, algo, factory)

    def getAsymmetricEncryptionAlgorithm(self, algo, provider=None):
        self.ensureLoaded()
        return self.asymmetricEncryptionAlgos.get(algo, provider)

    def setProviderForAsymmetricEncryptionAlgo(self, algo, provider):
        self.asymmetricEncryptionAlgos.setProviderForAlgorithm(algo, provider)

    def registerPBKDF(self, provider, algo, impl):
        assert callable(impl)
        self.pbkdfAlgos.add(provider, algo, impl)

    def getPBKDFAlgorithm(self, algo, provider=None):
        self.ensureLoaded()
        return self.pbkdfAlgos.get(algo, provider)

    def setProviderForPBKDFAlgo(self, algo, provider):
        self.pbkdfAlgos.setProviderForAlgorithm(algo, provider)

    def registerMAC(self, provider, algo, impl):
        assert callable(impl)
        self.macAlgos.add(provider, algo, impl)

    def getMACAlgorithm(self, algo, provider=None):
        self.ensureLoaded()
        return self.macAlgos.get(algo, provider)

    def setProviderForMACAlgo(self, algo, provider):
        self.macAlgos.setProviderForAlgorithm(algo, provider)


Algorithms = CryptoAlgorithmRegistry(
    pathlib.Path(__file__).parent, __package__)
