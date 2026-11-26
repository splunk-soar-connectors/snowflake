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

from soar_sdk.app import App

from .actions.connectivity import test_connectivity
from .actions.describe_network_policy import (
    NetworkPolicyProperty,
    describe_network_policy,
)
from .actions.disable_user import DisableUserSummary, disable_user
from .actions.remove_grants import remove_grants
from .actions.run_query import QueryRow, QuerySummary, run_query
from .actions.show_network_policies import (
    NetworkPolicy,
    NetworkPolicySummary,
    show_network_policies,
)
from .actions.statement import StatementResult
from .actions.update_network_policy import update_network_policy
from .asset import Asset
from .views import QueryWidgetMeta, display_query_results


app = App(
    name="Snowflake",
    app_type="siem",
    logo="logo_snowflake.svg",
    logo_dark="logo_snowflake_dark.svg",
    product_vendor="Snowflake",
    product_name="Snowflake",
    publisher="Splunk",
    appid="9dc1ac34-cac9-41fb-af81-e71ffe256f49",
    python_version="3.13",
    fips_compliant=False,
    asset_cls=Asset,
)


app.test_connectivity()(test_connectivity)

# These handlers return explicit SDK ActionResults. Register their published
# output schemas separately from the runtime return value.
app.action(
    description="Perform a SQL query",
    action_type="investigate",
    read_only=False,
    output_class=QueryRow,
    view_handler=display_query_results,
    summary_type=QuerySummary,
)(run_query)

app.action(
    description="Prevent a Snowflake user from starting new sessions. Existing sessions are not terminated",
    action_type="investigate",
    read_only=False,
    output_class=StatementResult,
    render_as="table",
    summary_type=DisableUserSummary,
)(disable_user)

app.action(
    description="List available network policies",
    action_type="investigate",
    read_only=True,
    output_class=NetworkPolicy,
    view_handler=display_query_results,
    summary_type=NetworkPolicySummary,
)(show_network_policies)

app.action(
    description="List the details of a network policy",
    action_type="investigate",
    read_only=True,
    output_class=NetworkPolicyProperty,
    view_handler=display_query_results,
)(describe_network_policy)

app.action(
    description="Update an existing network policy",
    action_type="investigate",
    read_only=False,
    output_class=StatementResult,
    render_as="table",
)(update_network_policy)

app.action(
    description="Remove a specified granted role from a Snowflake user",
    action_type="investigate",
    read_only=False,
    output_class=StatementResult,
    render_as="table",
)(remove_grants)

for identifier, title in (
    ("run_query", "Execute Query"),
    ("show_network_policies", "Show Network Policies"),
    ("describe_network_policy", "Describe Network Policy"),
):
    action = app.get_actions()[identifier]
    action.meta = QueryWidgetMeta(**dict(action.meta), widget_title=title)


if __name__ == "__main__":
    app.cli()
