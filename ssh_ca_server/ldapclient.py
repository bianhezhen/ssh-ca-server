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
import ldap
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

        try:
            conn = ldap.initialize('ldaps://{}'.format(self.ldap_server))
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            upn = "{}@{}".format(self.bind_user, self.ldap_domain)
            conn.simple_bind_s(upn, self.bind_password)
            self.logger.debug("ldap_bind: Successful bind with bind_user={}".format(upn))

        except ldap.LDAPError as error:
            self.logger.error("ldap_bind: Bind error occurred: {}".format(error))
            return False

        return conn

    def check_auth(self, username, password):
        """ Bind with user credentials to verify username and password """

        upn = "{}@{}".format(username, self.ldap_domain)

        try:
            conn = ldap.initialize("ldaps://{}".format(self.ldap_server))
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.simple_bind_s(upn, password)

            user_filter = "(&(objectClass=person)(sAMAccountName={}))".format(username)
            self.logger.debug("check_auth: ldap filter {}".format(user_filter))
            conn.search_ext_s(self.base_dn, ldap.SCOPE_SUBTREE, user_filter)

            conn.unbind_s()

        except ldap.LDAPError as error:
            self.logger.debug("check_auth: Failed bind with user={} {}".format(upn, error))
            return False

        self.logger.debug("check_auth: Successful bind for {}".format(upn))
        return True

    def is_member(self, user_name, group_name):
        """ Determine if user_name is a member of ldap group """

        found = False

        # Using sAMAccountName get users full DN
        user_filter = "(&(objectClass=person)(sAMAccountName={}))".format(user_name)
        results = self.ldap_connection.search_ext_s(self.base_dn, ldap.SCOPE_SUBTREE, user_filter)
        user_dn = results[0][0]

        if user_dn is None:
            self.logger.error("is_member: User {} does not exist".format(user_name))

        else:
            self.logger.debug("is_member: Set user_dn={}".format(user_dn))

            # Using sAMAccountName get groups full DN
            self.logger.debug("is_member: Searching for group {}".format(group_name))
            group_filter = "(&(objectClass=group)(sAMAccountName={}))".format(group_name)

            results = self.ldap_connection.search_ext_s(self.base_dn, ldap.SCOPE_SUBTREE, group_filter)
            if results[0][0] is None:
                self.logger.debug("is_member: Group {} does not exist".format(group_name))

            elif "member" not in results[0][1]:
                self.logger.debug("is_member: Group {} does not have any members".format(group_name))

            else:
                # Looking through groups member field check for users full DN
                group_members = results[0][1]["member"]
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
        results = self.ldap_connection.search_ext_s(self.group_dn, ldap.SCOPE_SUBTREE, user_filter)

        roles_list = []

        for group in results:
            if group[0] is not None:
                role_dict = {}

                # Allow for a blank description
                try:
                    role_dict["description"] = group[1][self.role_description][0]
                except KeyError:
                    role_dict["description"] = ""

                try:
                    role_dict["name"] = group[1]["name"][0]
                    role_dict["ldap_group"] = group[1]['name'][0]
                    role_dict["allowed_cas"] = group[1][self.ca_attribute][0]
                    role_dict["allowed_principals"] = group[1][self.principal_attribute][0]
                    roles_list.append(role_dict)
                    self.logger.debug("get_roles: Found role {}".format(json.dumps(role_dict)))

                except KeyError:
                    self.logger.debug("get_roles: Verify group {} has all required attributes".format(group[0]))

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
