#!/usr/bin/env python3.4
import sys

if sys.version_info[:2] < (3, 4):
    print("Minimal python version is 3.4")


params = dict(
    name='s5',
    description='Secure Self hosted Synchronization and Sharing Service (S5)',
    author='wonko@hanstool.org',
    version='0.0',
    packages=['s5'],
)

try:
    from setuptools import setup
    setup(
        install_requires=['pycrypto'],
        entry_points={
            'console_scripts': ['s5server = s5.server', 's5 = s5.client']
        },
        ** params
    )
except Exception as e:
    raise e
    from distutils.core import setup
    setup(**params)
    print("Please ensure you have `pycrypto` installed and create scripts"
          " in your PATH that execute `s5.client` and `s5.server`")
