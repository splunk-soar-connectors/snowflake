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

from src.utils import (
    build_network_policy_set_clause,
    escape_sql_string,
    format_ip_list,
    validate_identifier,
)
import pytest


class SnowflakeUtilsTest(unittest.TestCase):
    def test_validate_identifier_accepts_unquoted_snowflake_identifiers(self):
        for identifier in ("USER_1", "policy$name", "_ROLE"):
            with self.subTest(identifier=identifier):
                assert validate_identifier(identifier, "identifier") == identifier

    def test_validate_identifier_rejects_unsafe_values(self):
        for identifier in ("", "1user", "user name", 'user";drop table users;--'):
            with (
                self.subTest(identifier=identifier),
                pytest.raises(ValueError, match="Invalid identifier"),
            ):
                validate_identifier(identifier, "identifier")

    def test_format_ip_list_validates_and_quotes_ip_addresses_and_networks(self):
        assert (
            format_ip_list("192.0.2.1, 2001:db8::/32", "allowed_ip_list")
            == "'192.0.2.1','2001:db8::/32'"
        )

    def test_format_ip_list_rejects_invalid_values(self):
        for ip_list in (
            "192.0.2.1,",
            "192.0.2.999",
            "192.0.2.1'); drop table users;--",
        ):
            with (
                self.subTest(ip_list=ip_list),
                pytest.raises(ValueError, match="Invalid allowed_ip_list"),
            ):
                format_ip_list(ip_list, "allowed_ip_list")

    def test_escape_sql_string_doubles_single_quotes(self):
        assert escape_sql_string("it's restricted") == "it''s restricted"

    def test_escape_sql_string_preserves_literal_backslashes(self):
        assert escape_sql_string(r"C:\notes") == r"C:\\notes"

    def test_network_policy_clause_preserves_omitted_fields(self):
        assert build_network_policy_set_clause(comment="updated") == "comment='updated'"

    def test_network_policy_clause_clears_explicit_empty_list(self):
        assert (
            build_network_policy_set_clause(allowed_ip_list="") == "allowed_ip_list=()"
        )

    def test_network_policy_clause_updates_only_supplied_fields(self):
        assert (
            build_network_policy_set_clause(
                blocked_ip_list="192.0.2.0/24", comment="it's blocked"
            )
            == "blocked_ip_list=('192.0.2.0/24') comment='it''s blocked'"
        )

    def test_network_policy_clause_requires_an_update(self):
        with pytest.raises(ValueError, match="Provide at least one"):
            build_network_policy_set_clause()


if __name__ == "__main__":
    unittest.main()
