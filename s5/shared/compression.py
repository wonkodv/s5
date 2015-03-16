"""
    Wrapper arround compression functions
"""

from ..plugins.compression import Algorithms


class CompressionError(Exception):
    pass


def getCompressionAlgorithm(algo):
    return Algorithms.getCompressionAlgorithm(algo)


def setProviderForCompressionAlgorithm(self, algo, provider):
    Algorithms.setProviderForCompressionAlgorithm(self, algo, provider)
