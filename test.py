#!/usr/bin/python3 -Bbb

"""
    Test script for all s5 unit tests
"""

import pstats
import warnings
import traceback
import io
import logging
import sys
from pathlib import Path
import coverage
import unittest
import cProfile

logOutput = io.StringIO()
logging.basicConfig(
    level=logging.DEBUG,
    stream=logOutput,
    format="%(pathname)s:%(lineno)d: %(levelname)-10s  %(message)s")

warnings.filterwarnings('once')

cov = coverage.coverage(branch=True, omit=('test.py',))
suite = unittest.TestSuite()


pr = cProfile.Profile()
pr.enable()
cov.start()

dataDir = Path(__file__).parent

# Test Precedence:
# 1 commandline (module[.class[.method]])
# 2 failures.txt (same format)
# 3 **/test_*.py

tests = []


def addFile(m):
    m = m.with_suffix("")
    m = str(m)
    m = m.replace("/", ".")
    tests.append(m)

if sys.argv[1:] == []:
    sys.argv.append('--all')
for a in sys.argv[1:]:
    if a == '--failures' or a == "-f":
        p = (dataDir / '.failures')
        if p.exists():
            with p.open('rt') as f:
                tests.extend(map(lambda s: s.strip(), f))
    elif '/' in a:
        addFile(Path(a))
    elif a == '--all':
        p = Path(__file__).resolve().parent
        for mp in p.glob("**/test_*.py"):
            m = mp.relative_to(p)
            addFile(m)
    else:
        tests.append(a)

for m in tests:
    if Path('/'.join(m.split('.')) + '.py').exists():
        # Better Errors
        __import__(m)
    t = unittest.defaultTestLoader.loadTestsFromName(m)
    suite.addTest(t)

result = unittest.TextTestRunner().run(suite)


cov.stop()
pr.disable()


with (dataDir / '.testcoverage').open('wt') as f:
    cov.report(file=f, show_missing=False)

failedmodules = set()
with (dataDir / '.failures').open('wt') as f:
    for x, y in result.errors + result.failures:
        f.write(x.id() + "\n")
        failedmodules.add(x.__module__)

with (dataDir / '.failedmodules').open('wt') as t:
    for x in failedmodules:
        t.write(sys.modules[x].__file__ + "\n")

with (dataDir / '.profile').open('wt') as f:
    ps = pstats.Stats(pr, stream=f).sort_stats('cumtime')
    ps.print_stats()

if len(result.errors) > 0:
    sys.exit(2)
if len(result.failures) > 0:
    sys.exit(1)

print(logOutput.getvalue())

cov.report(show_missing=False)
