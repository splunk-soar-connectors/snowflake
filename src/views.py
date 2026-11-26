# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import re

from soar_sdk.meta.actions import ActionMeta
from soar_sdk.views.template_renderer import get_template_renderer, get_templates_dir


class QueryWidgetMeta(ActionMeta):
    """Preserve the legacy layout for these custom views."""

    widget_title: str

    def model_dump(self, *args, **kwargs):
        metadata = super().model_dump(*args, **kwargs)
        metadata.pop("widget_title", None)
        metadata["render"].update(width=10, height=5, title=self.widget_title)
        return metadata


def display_query_results(_action, all_app_runs, context):
    # The SOAR custom view protocol supplies full results, including empty
    # ones. The SDK's row-based view decorator flattens those boundaries.
    tables = []
    for _, action_results in all_app_runs:
        for result in action_results:
            rows = result.get_data()
            headers = sorted(rows[0]) if rows else []
            tables.append(
                {
                    "headers": headers,
                    "data": [
                        [{"value": row.get(column)} for column in headers]
                        for row in rows
                    ],
                }
            )

    renderer = get_template_renderer(templates_dir=get_templates_dir(globals()))
    html = renderer.render_template(
        "query_results.html", {**context, "results": tables}
    )
    context["prerender"] = True
    # The SOAR widget loader expects the first node to be an element.
    return re.sub(r"^\s*(?:<!--.*?-->\s*)+", "", html, flags=re.DOTALL)
