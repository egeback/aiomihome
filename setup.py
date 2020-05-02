#!/usr/bin/env python
from aiomihome.constants import __version__, REQUIRED_PYTHON_VER
from setuptools import setup, find_packages


PROJECT_NAME = 'Xiaomi Hub API'
PROJECT_PACKAGE_NAME = 'aiomihome'
PROJECT_LICENSE = 'MIT'
PROJECT_AUTHOR = 'Marky Egebäck'
PROJECT_EMAIL = 'marky@egeback.se'
PROJECT_URL = 'https://github.com/egeback/aiomihome'
DOWNLOAD_URL = 'https://github.com/egeback/aiomihome/archive/v1.0.3.zip'
PROJECT_DESCRIPTION = 'Python asyncio implementation of Xiaomi Aqara Hub API'
PACKAGES = find_packages(exclude=['tests', 'tests.*'])


REQUIRES = []

MIN_PY_VERSION = '.'.join(map(str, REQUIRED_PYTHON_VER))

import unittest
def my_test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests', pattern='test_*.py')
    return test_suite

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    long_description=long_description,
    long_description_content_type="text/markdown",
    name=PROJECT_PACKAGE_NAME,
    version=__version__,
    license=PROJECT_LICENSE,
    url=PROJECT_URL,
    download_url=DOWNLOAD_URL,
    author=PROJECT_AUTHOR,
    author_email=PROJECT_EMAIL,
    description=PROJECT_DESCRIPTION,
    packages=PACKAGES,
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=REQUIRES,
    python_requires='>={}'.format(MIN_PY_VERSION),
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    #test_suite='setup.my_test_suite',
    test_suite='tests',
    keywords=['xiaomi', 'aqara'],
    entry_points={},
    # classifiers=PROJECT_CLASSIFIERS,
)