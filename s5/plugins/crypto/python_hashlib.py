""" Wrapper around python's hashlib module """
import hashlib


class HashFactory:

    def __init__(self, algo):
        self.algo = algo

    def __call__(self):
        return hashlib.new(self.algo)


def Register(registry):
    provider = "hashlib"

    for algo in "sha1", "sha512", "sha256", "sha384", "ripemd160", "whirlpool":
        registry.registerHashAlgorithm(provider, algo, HashFactory(algo))
