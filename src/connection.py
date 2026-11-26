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
from contextlib import closing, contextmanager
from datetime import date, timedelta
from typing import Any

from soar_sdk.action_results import ActionResult
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Params

from .asset import Asset
from .consts import DEFAULT_NUM_ROWS_TO_FETCH, SNOWFLAKE_ERROR_MSG_UNAVAILABLE
from .utils import validate_identifier


class SnowflakeActionFailure(ActionFailure):
    """Keep legacy action messages while using the SDK failure path."""

    def __str__(self) -> str:
        return self.message


@contextmanager
def action_result(params: Params) -> Iterator[ActionResult]:
    # The SDK's automatic failure result drops inputs and any rows read before
    # an exception. Retain both on the same result that receives the error.
    result = ActionResult(
        status=True,
        message="",
        param=params.model_dump(by_alias=True, exclude_none=True),
    )
    try:
        yield result
    except SnowflakeActionFailure as error:
        result.set_status(False, str(error))


def validated_identifier(value: str, parameter_name: str) -> str:
    try:
        return validate_identifier(value, parameter_name)
    except ValueError as error:
        raise SnowflakeActionFailure(str(error)) from error


@contextmanager
def open_cursor(
    asset: Asset,
    *,
    dictionaries: bool = False,
    error_prefix: str | None = None,
    **settings: Any,
) -> Iterator:
    # Manifest generation can run in an SDK environment without the app's driver.
    from snowflake.connector import DictCursor, connect  # noqa: PLC0415

    try:
        with (
            closing(
                connect(
                    account=asset.account,
                    user=asset.username,
                    password=asset.password,
                    **settings,
                )
            ) as connection,
            closing(
                connection.cursor(DictCursor) if dictionaries else connection.cursor()
            ) as cursor,
        ):
            yield cursor
    except Exception as error:
        if len(error.args) > 1:
            message = f"Error Code: {error.args[0]}. Error Message: {error.args[1]}"
        else:
            message = f"Error Message: {error.args[0] if error.args else SNOWFLAKE_ERROR_MSG_UNAVAILABLE}"
        raise SnowflakeActionFailure(
            f"{error_prefix}: {message}" if error_prefix else message
        ) from error


def fetch_rows(cursor: Any) -> Iterator:
    while batch := cursor.fetchmany(DEFAULT_NUM_ROWS_TO_FETCH):
        yield from batch


def json_value(value: Any) -> Any:
    if isinstance(value, bytes | bytearray):
        return value.decode("utf-8")
    if isinstance(value, date | timedelta):
        return str(value)
    return value


def normalize_row(row: dict) -> dict:
    return {column: json_value(value) for column, value in row.items()}
