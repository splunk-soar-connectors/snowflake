# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from ..asset import Asset
from ..connection import SnowflakeActionFailure, open_cursor
from ..consts import (
    SNOWFLAKE_VERSION_QUERY,
    TEST_CONNECTIVITY_ERROR_MSG,
    TEST_CONNECTIVITY_PROGRESS_MSG,
    TEST_CONNECTIVITY_SUCCESS_MSG,
)


logger = getLogger()


def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    logger.progress(TEST_CONNECTIVITY_PROGRESS_MSG)
    try:
        with open_cursor(asset) as cursor:
            cursor.execute(SNOWFLAKE_VERSION_QUERY)
    except ActionFailure as error:
        logger.progress(str(error))
        raise SnowflakeActionFailure(TEST_CONNECTIVITY_ERROR_MSG) from error
    soar.set_message(TEST_CONNECTIVITY_SUCCESS_MSG)
