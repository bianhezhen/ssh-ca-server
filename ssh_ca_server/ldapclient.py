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
    ssh_ca_server.ldapclient
    ~~~~~~~~~~~~~~~~~~~~

    LDAP interface
"""

import logging
import ldap3
import json
from .config import Config


class LdapClient(object):

    def __init__(self):

        self.logger = logging.getLogger("ca_server")

        self.ldap_server = Config.ldap_server
        self.bind_user = Config.bind_user
        self.bind_password = Config.bind_password
        self.ldap_domain = Config.ldap_domain
        self.base_dn = Config.base_dn
        self.group_dn = Config.group_dn
        self.role_attribute = Config.role_attribute
        self.role_description = Config.role_description
        self.ca_attribute = Config.ca_attribute
        self.principal_attribute = Config.principal_attribute

        self.ldap_connection = self.ldap_bind()

    def ldap_bind(self):
        """ Establish ldap connection """

        bind_upn = "{}@{}".format(self.bind_user, self.ldap_domain)

        server = ldap3.Server(host=self.ldap_server, port=636, use_ssl=True, get_info='ALL')

        conn = ldap3.Connection(server, user=bind_upn, password=self.bind_password, auto_bind='NONE', version=3,
                                authentication='SIMPLE', client_strategy='SYNC', auto_referrals=False,
                                check_names=True, read_only=True, lazy=False, raise_exceptions=False)

        if not conn.bind():
            self.logger.error("ldap_bind: Bind error occurred: {}".format(conn.result))
            return False

        return conn

    def check_auth(self, username, password):
        """ Bind with user credentials to verify username and password """

        if password is not "":

            upn = "{}@{}".format(username, self.ldap_domain)

            server = ldap3.Server(host=self.ldap_server, port=636, use_ssl=True, get_info='ALL')

            conn = ldap3.Connection(server, user=upn, password=password, auto_bind='NONE', version=3,
                                    authentication='SIMPLE', client_strategy='SYNC', auto_referrals=False,
                                    check_names=True, read_only=True, lazy=False, raise_exceptions=False)

            if conn.bind():
                return True
            else:
                return False

        return False

    def sanitizeLDAP(self, ldap_string):
        return ldap_string.replace("\\","\\5c")\
                          .replace("*","\\2a")\
                          .replace("(","\\28")\
                          .replace(")","\\29")\
                          .replace("\0","\\00")


    def is_member(self, user_name, group_name):
        """ Determine if user_name is a member of ldap group """

        found = False
        user_name = self.sanitizeLDAP(user_name)
        group_name = self.sanitizeLDAP(group_name)

        # Using sAMAccountName get users full DN
        user_filter = "(&(objectClass=person)(sAMAccountName={}))".format(user_name)

        self.ldap_connection.search(search_base=self.base_dn,
                                    search_filter=user_filter,
                                    search_scope=ldap3.SUBTREE,
                                    attributes=["distinguishedName",
                                                "userPrincipalName"]
                                    )

        if "attributes" not in self.ldap_connection.response[0]:
            self.logger.error("is_member: User {} does not exist".format(user_name))

        else:

            user_dn = self.ldap_connection.response[0]["attributes"]["distinguishedName"]

            self.logger.debug("is_member: Set user_dn={}".format(user_dn))

            # Using sAMAccountName get groups full DN
            self.logger.debug("is_member: Searching for group {}".format(group_name))
            group_filter = "(&(objectClass=group)(sAMAccountName={}))".format(group_name)

            self.ldap_connection.search(search_base=self.base_dn,
                                        search_filter=group_filter,
                                        search_scope=ldap3.SUBTREE,
                                        attributes=["member"]
                                        )

            if len(self.ldap_connection.response) == 0:
                self.logger.debug("is_member: Group {} does not exist".format(group_name))

            elif "member" not in self.ldap_connection.response[0]["attributes"]:
                self.logger.debug("is_member: Group {} does not have any members".format(group_name))

            else:
                # Looking through groups member field check for users full DN
                group_members = self.ldap_connection.response[0]["attributes"]["member"]
                for member in group_members:
                    if member == user_dn:
                        self.logger.debug("is_member: Validated user {} is a member of {}".format(user_dn, group_name))
                        found = True  # Hey, I found you... :)

        return found

    def get_roles(self):
        """
        Get list of roles based on LDAP groups that have role_attribute = ca-role
        LDAP attributes store the authorized CAs and principals
        """

        # Find all groups with 'ca-role' in the role_attribute
        user_filter = "(&(objectClass=group)({}=ca-role))".format(self.role_attribute)

        self.ldap_connection.search(search_base=self.group_dn,
                                    search_filter=user_filter,
                                    search_scope=ldap3.SUBTREE,
                                    attributes=['name',
                                                self.role_description,
                                                self.ca_attribute,
                                                self.principal_attribute
                                                ]
                                    )

        roles_list = []

        for group in self.ldap_connection.response:
            if group["attributes"]["name"] is not None:
                role_dict = {}

                # Allow for a blank description
                try:
                    role_dict["description"] = group["attributes"][self.role_description][0]
                except IndexError:
                    role_dict["description"] = ""

                try:
                    role_dict["name"] = group["attributes"]["name"]
                    role_dict["ldap_group"] = group["attributes"]["name"]
                    role_dict["allowed_cas"] = group["attributes"][self.ca_attribute]
                    role_dict["allowed_principals"] = group["attributes"][self.principal_attribute]
                    roles_list.append(role_dict)
                    self.logger.debug("get_roles: Found role {}".format(json.dumps(role_dict)))

                except KeyError:
                    self.logger.debug("get_roles: Verify group {} has all required attributes".format(group["name"]))

        return roles_list

    def get_authorized_principals(self, username, requested_ca):
        """ Get complete list of authorized principals for given user """

        roles_list = self.get_roles()
        principals = list()

        # Always sign with the username in addition to all authorized principals
        principals.append(username)

        for role in roles_list:
            ldap_group = role['ldap_group']
            allowed_cas = role['allowed_cas'].split(',')

            if requested_ca in allowed_cas:
                if self.is_member(username, ldap_group):
                    allowed_principals = role['allowed_principals']
                    for principal in allowed_principals.split(','):
                        principals.append(principal)

        return principals
