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
    ssh_ca_server.logger
    ~~~~~~~~~~~~~~~~~~~~

    Setup logging
"""

import logging
from .config import Config


def setup_logger():
    """ Configure logging options """

    log_level = Config.log_level
    log_file = Config.log_file

    logger = logging.getLogger("ca_server")

    logger.setLevel(log_level)

    fh = logging.FileHandler(log_file)
    fh.setLevel(log_level)

    formatter = logging.Formatter(
        "%(asctime)-15s - %(levelname)s - %(module)s - %(message)s")
    fh.setFormatter(formatter)

    logger.addHandler(fh)

    logger.info("Started CA Server")

    logger.info("Loading configuration from {}".format(Config.config_path))
