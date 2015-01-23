""" Registry of compression algorithms """
import pathlib

from .. import BaseRegistry
from .. import AlgorithmProviderStore


class CompressionAlgorithmRegistry(BaseRegistry):

    def __init__(self, path, package):
        super().__init__(path, package)
        self.compressionAlgorithms = AlgorithmProviderStore()

    def registerCompressionAlgorithm(self, provider, algo, factory):
        """ register a factory that returns new compressors and decompressors"""
        assert callable(factory.getCompressor)
        assert callable(factory.getDecompressor)
        self.compressionAlgorithms.add(provider, algo, factory)

    def getCompressionAlgorithm(self, algo, provider=None):
        self.ensureLoaded()
        return self.compressionAlgorithms.get(algo, provider)

    def setProviderForCompressionAlgorithm(self, algo, provider):
        return self.compressionAlgorithms.setProviderForAlgorithm(
            algo,
            provider)


Algorithms = CompressionAlgorithmRegistry(
    pathlib.Path(__file__).parent, __package__)
