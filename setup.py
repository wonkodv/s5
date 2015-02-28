#!/usr/bin/env python

from setuptools import setup

setup(
    name='s5',
    description='Secure Self hosted Synchronization and Sharing Service (S5)',
    author='Matthias Riegel',
    version='0.0',
    packages=['s5'],
    entry_points={'console_scripts': ['s5server = s5.server', 's5 = s5.client']}
)
