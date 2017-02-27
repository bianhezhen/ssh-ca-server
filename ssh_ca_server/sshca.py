# -*- coding: utf-8 -*-

# Copyright 2016 Commerce Technologies, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
    ssh_ca_server.sshca
    ~~~~~~~~~~~~~~~~~~~~

    Implement all SSH CA methods
"""

import subprocess
import os
import stat
import logging
import random
from .config import Config


class CA(object):

    # Default for key signing expiration
    DEFAULT_MAX_DURATION = 7

    def __init__(self, ca_name):

        self.logger = logging.getLogger('ca_server')

        self.public_key = None
        self.ca_name = ca_name
        self.ca_config = Config.get_ca_configuration(ca_name)

        if len(self.ca_config) == 0:
            raise ValueError("Requested CA does not exist")

        self.ca_path = Config.ca_path

        self.logger.debug("__init__: Using default CA configuration {}".format(self.ca_path))

        if self.ca_config:

            if "max_duration" in self.ca_config:
                self.max_duration = self.ca_config['max_duration']
            else:
                self.max_duration = CA.DEFAULT_MAX_DURATION

            self.ca_file_path = self.full_path(self.ca_path, self.ca_name)

            if (os.path.isfile(self.ca_file_path)):
                public_key = open("{}.pub".format(self.ca_file_path))
                # Remove junk around public key so we can add it back later :)
                self.public_key = public_key.read().split(' ')[1]
            else:
                self.logger.debug("__init__: Creating CA for {}".format(self.ca_name))
                self.create_ca()

    @staticmethod
    def full_path(dir_name, file_name):
        """ Consturct full file path """

        if dir_name[len(dir_name)-1:] == "/":
            file_path = '{}{}'.format(dir_name, file_name)
        else:
            file_path = '{}/{}'.format(dir_name, file_name)

        return file_path

    def mkdir_recursive(self, path):
        """ Recursively create directory """

        sub_path = os.path.dirname(path)
        if not os.path.exists(sub_path):
            self.mkdir_recursive(sub_path)
        if not os.path.exists(path):
            os.mkdir(path)

    def create_ca(self):
        """ Create a new CA """

        temp_ca_key_file = '/tmp/{}'.format(self.ca_name)
        temp_ca_cert_file = '{}.pub'.format(temp_ca_key_file)

        ca_key_file = self.full_path(self.ca_path, self.ca_name)
        ca_cert_file = '{}.pub'.format(ca_key_file)

        subprocess.call(['ssh-keygen',
                         '-f', temp_ca_key_file,
                         '-q', '-P', ''])

        if not os.path.exists(self.ca_path):
            self.mkdir_recursive(self.ca_path)

        # If CA was successfully created move it to the correct location and
        # set appropriate permissions
        if os.path.isfile(temp_ca_key_file) and os.path.isfile(temp_ca_cert_file):

            os.rename(temp_ca_cert_file, ca_cert_file)
            os.chmod(ca_cert_file, stat.S_IRUSR)

            os.rename(temp_ca_key_file, ca_key_file)
            os.chmod(ca_key_file, stat.S_IRUSR)

    def sign_cert(self, user, principals, filename):
        """ Sign an ssh public key file """

        principal_list = ','.join(principals)

        # No idea what purpose the serial number has... Why not generate a
        # random 64bit value?
        serial = random.getrandbits(64)

        if self.public_key:
            subprocess.call([
                'ssh-keygen',
                '-s', '{}/{}'.format(self.ca_path, self.ca_name),
                '-z', str(serial),
                '-I', user,
                '-V', '+{}'.format(self.max_duration),
                '-n', principal_list,
                '-q',
                filename])

            cert_file_name = filename.split(".")[0] + "-cert.pub"

            if os.path.isfile(cert_file_name):
                return cert_file_name

        return False

    def get_public_key(self):
        """ Get the public key of a CA """
        return self.public_key
