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
    ssh_ca_server.config
    ~~~~~~~~~~~~~~~~~~~~

    Get configuration from file
"""

import json
import os


class Config(object):

    config_path = os.getenv('SSHCA_CONFIG_PATH', "/etc/ca-server/config.json")

    role_attribute = "extensionAttribute1"
    role_description = "description"
    ca_attribute = "extensionAttribute2"
    principal_attribute = "extensionAttribute3"
    ca_path = "/etc/ca-server/certs"
    upload_folder = "/tmp"
    cas = None
    ldap_server = None
    ldap_domain = None
    bind_user = None
    bind_password = None
    base_dn = None
    group_dn = None
    log_level = "INFO"
    log_file = "/var/log/ca-server/server.log"

    # Configuration keys that must be provided to override defaults
    required_configuration = ["cas",
                              "ldap_server",
                              "ldap_domain",
                              "bind_user",
                              "bind_password",
                              "base_dn",
                              "group_dn"]

    def __init__(self):

        if not Config.load_configuration():
            raise ValueError("Failed to load configuration from {}".format(Config.config_path))

        if not Config.validate_required_configuration():
            raise ValueError("Required configuration missing")

    @classmethod
    def validate_required_configuration(cls):
        """ Validate that all required configuration has been provided

        :rtype: bool: False if any expected configuration parameter was not provided

        """

        valid = True

        for key in cls.required_configuration:
            if getattr(cls, key) is None:
                print(key)
                valid = False

        return valid

    @classmethod
    def load_configuration(cls):
        """ Load configuration from file

        :rtype: bool: False if configuration does not exist or is invalid json

        """

        if os.path.isfile(Config.config_path):
            with open(Config.config_path, 'r') as config_file:
                try:
                    loaded_config = json.loads(config_file.read())
                except ValueError as error:
                    print("Configuration is not valid yaml ({})".format(cls.config_path))
                    print(error)
                    return False

            for key in loaded_config:
                setattr(cls, key, loaded_config[key])

        else:
            return False

        return True

    @classmethod
    def get_ca_configuration(cls, ca_name):
        """ Get list of CAs from configuration

        :rtype: list: Returns list of CAs loaded from configuration file

        """
        for cert_authority in cls.cas:
            if ca_name == cert_authority['name']:
                return cert_authority

        # Return an empty list if no CA was found
        return []
