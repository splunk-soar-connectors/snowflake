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

from collections.abc import Iterator

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import (
    ActionOutput,
    OutputFieldSpecification,
    PermissiveActionOutput,
)
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..connection import fetch_rows, normalize_row, open_cursor
from ..consts import SQL_QUERY_ERROR_MSG


class RunQueryParams(Params):
    query: str = Param(
        description="Query string", primary=True, cef_types=["sql query"]
    )
    role: str | None = Param(description="Role to use to execute action")
    warehouse: str | None = Param(description="Warehouse")
    database: str | None = Param(description="Database")
    schema_name: str | None = Param(
        description="Schema", required=False, alias="schema"
    )


class QueryRow(PermissiveActionOutput):
    @classmethod
    def _to_json_schema(
        cls, parent_datapath="action_result.data.*", column_order_counter=None
    ) -> Iterator[OutputFieldSpecification]:
        # SQL determines column names at runtime. Retain the existing aggregate
        # data path so playbooks can still select the entire result collection.
        yield {"data_path": parent_datapath.removesuffix(".*"), "data_type": "string"}


class QuerySummary(ActionOutput):
    total_rows: int


def unique_column_names(description) -> list[str]:
    names = []
    used = set()
    for index, column in enumerate(description or ()):
        name = column.name if hasattr(column, "name") else column[0]
        if name in used:
            duplicate = f"{name}__duplicate_{index}"
            name = duplicate
            suffix = 1
            while name in used:
                name = f"{duplicate}_{suffix}"
                suffix += 1
        used.add(name)
        names.append(name)
    return names


def run_query(params: RunQueryParams, soar: SOARClient, asset: Asset) -> list[QueryRow]:
    with open_cursor(
        asset,
        error_prefix=SQL_QUERY_ERROR_MSG,
        role=params.role,
        warehouse=params.warehouse,
        database=params.database,
        schema=params.schema_name,
    ) as cursor:
        cursor.execute(params.query)
        names = unique_column_names(cursor.description)
        rows = (
            [
                QueryRow(**normalize_row(dict(zip(names, row, strict=True))))
                for row in fetch_rows(cursor)
            ]
            if names
            else []
        )
        total_rows = max(cursor.rowcount or 0, 0)
    soar.set_summary(QuerySummary(total_rows=total_rows))
    return rows
