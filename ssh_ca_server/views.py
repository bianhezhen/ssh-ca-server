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
    ssh_ca_server.views
    ~~~~~~~~~~~~~~~~~~~~

    Implement Flask views
"""

from functools import wraps
import logging
from flask import request
import os

from . import app
from .config import Config
from .databag import DataBag
from .ldapclient import LdapClient
from .sshca import CA


def requires_auth(function):
    """ Bind against LDAP to validate users credentials """

    @wraps(function)
    def decorated(*args, **kwargs):

        logger = logging.getLogger("ca_server")
        auth = request.authorization
        ldap = LdapClient()

        if not auth or not ldap.check_auth(auth.username, auth.password):
            output = DataBag()
            output.set_error("Access denied")
            if hasattr(auth, "username"):
                logger.info("requires_auth: access denied {}".format(auth.username))
            else:
                logger.info("requires_auth: access denied")
            return output.get_json()

        return function(auth.username)
    return decorated

@app.route("/")
def app_root():
    """ Base URL request to support client version check & health check """

    output = DataBag()
    return output.get_json()

@app.route("/list/cas")
def list_cas():
    """ Return full list of available CAs """

    output = DataBag()
    output.set_payload(Config.cas)
    return output.get_json()

@app.route("/list/roles")
def list_roles():
    """ Return complete list of roles for given user """

    requested_username = request.args.get("user")
    output = DataBag()
    ldap = LdapClient()

    if ldap.ldap_connection:
        roles_list = ldap.get_roles()

        authorized_roles = []
        for role in roles_list:
            ldap_group = role['ldap_group']

            if ldap.is_member(requested_username, ldap_group):
                authorized_roles.append(role)

        output.set_payload(authorized_roles)
    else:
        output.set_error("Server issue, please contact your administrator")

    return output.get_json()

@app.route("/get/<ca_name>")
def get_key(ca_name):
    """ Return CA public key """

    output = DataBag()

    try:
        requested_ca = CA(ca_name)

    except ValueError:
        output.set_error("Requested CA does not exist")

    else:
        output.set_payload(requested_ca.public_key)

    return output.get_json()


@app.route("/sign", methods=["GET", "POST"])
@requires_auth
def sign_cert_request(username):
    """ Sign my public key!!! """

    logger = logging.getLogger("ca_server")
    requested_ca = request.args.get("ca")
    ldap = LdapClient()

    output = DataBag()

    allowed_principals = ldap.get_authorized_principals(username, requested_ca)

    if request.method == "POST" and len(allowed_principals) > 0:
        uploaded_file = request.files["file"]
        filename = os.path.join(Config.upload_folder, uploaded_file.filename)
        uploaded_file.save(filename)

        # Initialize requested CA and sign public key
        try:
            signing_ca = CA(requested_ca)
            cert_file = signing_ca.sign_cert(username, allowed_principals, filename)

        except ValueError:
            output.set_error("Requested CA does not exist")
            logger.info("sign_cert_request: {} requested invalid CA {}".format(username, requested_ca))

        else:
            signed_cert = open(cert_file).read()
            os.remove(cert_file)
            os.remove(filename)

            output.set_payload(signed_cert)
            logger.info("sign_cert_request: {} successful signing request for ({}) -> {}".format(
                        username, requested_ca, allowed_principals))

    else:
        output.set_error("Invalid or failed request, please check that you are using a valid CA")
        logger.info("sign_cert_request: {} invalid request".format(username))

    return output.get_json()
