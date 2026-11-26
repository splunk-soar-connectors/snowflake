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

from soar_sdk.action_results import ActionOutput, ActionResult, OutputField

from ..asset import Asset
from ..connection import open_cursor
from ..consts import SNOWFLAKE_DATABASE


class StatementResult(ActionOutput):
    status: str | None = OutputField(
        column_name="Status", example_values=["Statement executed successfully."]
    )


def execute_statement(
    result: ActionResult,
    asset: Asset,
    statement: str,
    *,
    role: str | None,
    error_prefix: str | None = None,
) -> None:
    with open_cursor(
        asset,
        dictionaries=True,
        database=SNOWFLAKE_DATABASE,
        role=role,
        error_prefix=error_prefix,
    ) as cursor:
        cursor.execute(statement)
        row = cursor.fetchone()
        if row is not None:
            result.add_data(row)
