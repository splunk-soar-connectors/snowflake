# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import types
import unittest


snowflake_package = types.ModuleType("snowflake")
snowflake_package.__path__ = []
snowflake_connector = types.ModuleType("snowflake.connector")
snowflake_connector.DictCursor = object
snowflake_package.connector = snowflake_connector
sys.modules.setdefault("snowflake", snowflake_package)
sys.modules.setdefault("snowflake.connector", snowflake_connector)

phantom_package = types.ModuleType("phantom")
phantom_package.__path__ = []
phantom_app = types.ModuleType("phantom.app")
phantom_app.APP_ERROR = 1
phantom_app.APP_SUCCESS = 0
phantom_action_result = types.ModuleType("phantom.action_result")
phantom_action_result.ActionResult = object
phantom_base_connector = types.ModuleType("phantom.base_connector")
phantom_base_connector.BaseConnector = object
phantom_package.app = phantom_app
sys.modules.setdefault("phantom", phantom_package)
sys.modules.setdefault("phantom.app", phantom_app)
sys.modules.setdefault("phantom.action_result", phantom_action_result)
sys.modules.setdefault("phantom.base_connector", phantom_base_connector)

from snowflake_connector import SnowflakeConnector


class SnowflakeConnectorTest(unittest.TestCase):
    def test_duplicate_column_names_keep_every_value_and_avoid_generated_name_collisions(self):
        description = [
            ("NAME",),
            ("NAME__duplicate_2",),
            ("NAME",),
            ("NAME",),
        ]

        names = SnowflakeConnector._get_unique_column_names(description)
        result = dict(zip(names, ("first", "existing", "second", "third")))

        self.assertEqual(
            result,
            {
                "NAME": "first",
                "NAME__duplicate_2": "existing",
                "NAME__duplicate_2_1": "second",
                "NAME__duplicate_3": "third",
            },
        )


if __name__ == "__main__":
    unittest.main()
