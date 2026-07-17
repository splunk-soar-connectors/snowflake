# File: test_snowflake_utils.py
#
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

import unittest

from snowflake_utils import escape_sql_string, format_ip_list, validate_identifier


class SnowflakeUtilsTest(unittest.TestCase):
    def test_validate_identifier_accepts_unquoted_snowflake_identifiers(self):
        for identifier in ("USER_1", "policy$name", "_ROLE"):
            with self.subTest(identifier=identifier):
                self.assertEqual(validate_identifier(identifier, "identifier"), identifier)

    def test_validate_identifier_rejects_unsafe_values(self):
        for identifier in ("", "1user", "user name", 'user";drop table users;--'):
            with self.subTest(identifier=identifier), self.assertRaisesRegex(ValueError, "Invalid identifier"):
                validate_identifier(identifier, "identifier")

    def test_format_ip_list_validates_and_quotes_ip_addresses_and_networks(self):
        self.assertEqual(format_ip_list("192.0.2.1, 2001:db8::/32", "allowed_ip_list"), "'192.0.2.1','2001:db8::/32'")

    def test_format_ip_list_rejects_invalid_values(self):
        for ip_list in ("192.0.2.1,", "192.0.2.999", "192.0.2.1'); drop table users;--"):
            with self.subTest(ip_list=ip_list), self.assertRaisesRegex(ValueError, "Invalid allowed_ip_list"):
                format_ip_list(ip_list, "allowed_ip_list")

    def test_escape_sql_string_doubles_single_quotes(self):
        self.assertEqual(escape_sql_string("it's restricted"), "it''s restricted")


if __name__ == "__main__":
    unittest.main()
