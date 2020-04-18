#!/usr/bin/env python
from aiomihome.constants import __version__, REQUIRED_PYTHON_VER
from setuptools import setup, find_packages


PROJECT_NAME = 'Xiaomi Hub API'
PROJECT_PACKAGE_NAME = 'aiomihome'
PROJECT_LICENSE = 'MIT'
PROJECT_AUTHOR = 'Marky Egebäck'
PROJECT_EMAIL = 'marky@egeback.se'
PROJECT_DESCRIPTION = 'Python asyncio implementation of Xiaomi Aqara Hub API'
PACKAGES = find_packages(exclude=['tests', 'tests.*'])


REQUIRES = []

MIN_PY_VERSION = '.'.join(map(str, REQUIRED_PYTHON_VER))

setup(
    name=PROJECT_PACKAGE_NAME,
    version=__version__,
    license=PROJECT_LICENSE,
    # url=PROJECT_URL,
    # download_url=DOWNLOAD_URL,
    author=PROJECT_AUTHOR,
    author_email=PROJECT_EMAIL,
    description=PROJECT_DESCRIPTION,
    packages=PACKAGES,
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=REQUIRES,
    python_requires='>={}'.format(MIN_PY_VERSION),
    test_suite='tests',
    keywords=['xiaomi', 'aqara'],
    entry_points={},
    # classifiers=PROJECT_CLASSIFIERS,
)