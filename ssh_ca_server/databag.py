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
    ssh_ca_server.databag
    ~~~~~~~~~~~~~~~~~~~~

    Object returned to the client for all requests
"""

import json


class DataBag(object):
    """ DataBag.get_json() returns the expected input for the client """

    # Client has a supported api_version and expects the server response to match
    # Increasing this value will result in all clients requiring an update
    VERSION = "1.01"

    def __init__(self):
        self.content = dict()
        self.content["error"] = False
        self.content["message"] = ""
        self.content["payload"] = ""
        self.content["version"] = DataBag.VERSION

    def set_error(self, message):
        """ Set DataBag error message to return to the client """
        self.content["error"] = True
        self.content["message"] = message

    def set_payload(self, message):
        """ Payload is used to send back signed cert """
        self.content["payload"] = message

    def get_json(self):
        """ Return dict as string """
        return json.dumps(self.content)
