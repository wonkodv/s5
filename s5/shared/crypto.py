""" Wrap cryptographic functions like hashing.

Different providers can be used,
each provider can implement different functions.
Shipped providers reside in plugins/crypto/
every file provides 1 provider,"""

import pdb
import math
from ..plugins.crypto import Algorithms


class DecryptionError(Exception):
    pass


def getRandomItemIdentifier():
    id = getRandomBits(128)
    return '%032X' % id


def getRandomBits(numBits):
    """ return an Integer with the lowest n bits randomized """
    assert numBits > 0
    rng = Algorithms.getRandomNumberGenerator()
    return rng.getrandbits(numBits)


def getRandomBytes(numBytes):
    rng = Algorithms.getRandomNumberGenerator()
    return bytes([rng.getrandbits(8) for i in range(0, numBytes)])


def getRandomInt(a, b):
    """ a <= X <= b """
    rng = Algorithms.getRandomNumberGenerator()
    return rng.randint(a, b)


def generateSymmetricEncryptionKey(numBytes):
    assert numBytes <= 100, "pass byte size, not bitsize"
    return getRandomBytes(numBytes)


def getHashAlgorithm(algo):
    return Algorithms.getHashAlgorithm(algo)


def getSymmetricEncryptionAlgorithm(algo):
    return Algorithms.getSymmetricEncryptionAlgorithm(algo)


def getAsymmetricEncryptionAlgorithm(algo):
    return Algorithms.getAsymmetricEncryptionAlgorithm(algo)


def getPBKDFAlgorithm(algo):
    return Algorithms.getPBKDFAlgorithm(algo)


def getMACAlgorithm(algo):
    return Algorithms.getMACAlgorithm(algo)


def setProviderForRandomNumberGenerator(provider):
    Algorithms.setProviderForRandomNumberGenerator(provider)


def setProviderForHashAlgo(algo, provider):
    Algorithms.setProviderForHashAlgo(algo, provider)


def setProviderForSymmetricEncryptionAlgo(algo, provider):
    Algorithms.setProviderForSymmetricEncryptionAlgo(algo, provider)


def setProviderForAsymmetricEncryptionAlgo(algo, provider):
    Algorithms.setProviderForAsymmetricEncryptionAlgo(algo, provider)


def setProviderForPBKDFAlgo(algo, provider):
    Algorithms.setProviderForPBKDFAlgo(algo, provider)


def setProviderForMACAlgo(algo, provider):
    Algorithms.setProviderForMACAlgo(algo, provider)
