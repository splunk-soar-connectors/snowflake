# File: snowflake_utils.py
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

import ipaddress
import re


SNOWFLAKE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,254}$")
MISSING = object()


def validate_identifier(value, parameter_name):
    if not isinstance(value, str) or not SNOWFLAKE_IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(
            f"Invalid {parameter_name}. Use an unquoted Snowflake identifier containing only letters, numbers, _, or $, "
            "starting with a letter or _."
        )
    return value


def format_ip_list(value, parameter_name):
    if not value or not value.strip():
        return ""

    formatted_ips = []
    for raw_ip in value.split(","):
        ip_value = raw_ip.strip()
        if not ip_value:
            raise ValueError(f"Invalid {parameter_name}: empty list entries are not allowed")
        try:
            ipaddress.ip_network(ip_value, strict=False)
        except ValueError as error:
            raise ValueError(f"Invalid {parameter_name} entry: {ip_value}") from error
        formatted_ips.append(f"'{ip_value}'")

    return ",".join(formatted_ips)


def escape_sql_string(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("Invalid comment: expected a string")
    return value.replace("'", "''")


def build_network_policy_set_clause(*, allowed_ip_list=MISSING, blocked_ip_list=MISSING, comment=MISSING):
    assignments = []

    if allowed_ip_list is not MISSING and allowed_ip_list is not None:
        assignments.append(f"allowed_ip_list=({format_ip_list(allowed_ip_list, 'allowed_ip_list')})")
    if blocked_ip_list is not MISSING and blocked_ip_list is not None:
        assignments.append(f"blocked_ip_list=({format_ip_list(blocked_ip_list, 'blocked_ip_list')})")
    if comment is not MISSING and comment is not None:
        assignments.append(f"comment='{escape_sql_string(comment)}'")

    if not assignments:
        raise ValueError("Provide at least one of allowed_ip_list, blocked_ip_list, or comment")

    return " ".join(assignments)
