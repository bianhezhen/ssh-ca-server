
# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path, environ

#
# Setup version information from environment variables. They are set in
# the build environment.
#
MAJOR_VERSION = 0
MINOR_VERSION = 0
BUILD_NUMBER = 0

if 'MAJOR_VERSION' in environ:
    MAJOR_VERSION = environ['MAJOR_VERSION']

if 'MINOR_VERSION' in environ:
    MINOR_VERSION = environ['MINOR_VERSION']

if 'BUILD_NUMBER' in environ:
    BUILD_NUMBER = environ['BUILD_NUMBER']

VERSION = '{0}.{1}.{2}'.format(MAJOR_VERSION, MINOR_VERSION, BUILD_NUMBER)

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ssh-ca-server',
    version=VERSION,

    description='SSH CA Server',
    long_description=long_description,

    url='https://github.com/commercehub-oss/ssh-ca-server',
    author='Commerce Technologies, LLC',

    packages=find_packages(),

    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    install_requires=[
        'python-ldap>=2.4.25',
        'flask>=0.11.1'
    ]
)
