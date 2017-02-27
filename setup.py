
# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path, environ
import subprocess

try:
    version = subprocess.check_output(['git', 'describe', '--tags']).decode('utf-8').rstrip()
except:
    version = '0.0.0'

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ssh-ca-server',
    version=version,

    description='SSH CA Server',
    long_description=long_description,

    url='https://github.com/commercehub-oss/ssh-ca-server',
    author='Commerce Technologies, LLC',

    packages=find_packages(),

    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'
    ],
    install_requires=[
        'ldap3>=2.2.1',
        'flask>=0.11.1'
    ]
)
