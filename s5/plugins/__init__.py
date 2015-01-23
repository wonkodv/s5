"""
    Common functionallity for all plugins
"""

import logging
import importlib.machinery


class PluginError(Exception):
    pass


class PluginDependencyMissing(PluginError):
    pass


class BaseRegistry:

    def __init__(self, path, package):
        self.path = path
        self.package = package
        self._loaded = False

    def ensureLoaded(self):
        if not self._loaded:
            self.loadPlugins(self.path, self.package)
            self._loaded = True

    def loadPlugins(self, path, package):
        loaderCls = importlib.machinery.SourceFileLoader
        for f in path.glob('*.py'):
            name = f.stem
            if not name.startswith("_"):
                name = package + '.' + name
                mod = loaderCls(name, str(f)).load_module()
                if not hasattr(mod, 'Register'):
                    raise AttributeError(
                        "plugin %s (%s) has no Register() function" %
                        (name, f,))
                else:
                    mod.Register(self)


class AlgorithmProviderStore:

    def __init__(self):
        self.algorithms = {}
        self.preferredProvider = {}

    def add(self, provider, algo, impl):
        """ add an implementation/factory of algorithm by provider """
        provider = provider.lower()
        algo = algo.lower()
        if algo not in self.algorithms:
            self.algorithms[algo] = {provider: impl}
            self.preferredProvider[algo] = provider
        else:
            self.algorithms[algo][provider] = impl

    def get(self, algo, provider=None):
        algo = algo.lower()
        if provider is None:
            provider = self.preferredProvider[algo]
        else:
            provider = provider.lower()
        return self.algorithms[algo][provider]

    def iterateAlgoProviders(self):
        for a in sorted(self.algorithms.keys()):
            for p in sorted(self.algorithms[a].keys()):
                yield a, p

    def __iter__(self):
        return iter(self.algorithms)

    def setProviderForAlgorithm(self, algo, provider):
        provider = provider.lower()
        algo = algo.lower()
        if provider in self.algorithms[algo]:
            self.preferredProvider[algo] = provider
        else:
            raise KeyError("No %s not provided by %s" % (algo, provider))


# the following Modules need above Classes:
from . import crypto
from . import compression
from . import items
