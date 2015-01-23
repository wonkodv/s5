""" Wrap pythons `random.SystemRandom` """
import random


def Register(registry):
    provider = "SystemRandom"
    registry.registerRandomNumberGenerator(provider, random.SystemRandom())
