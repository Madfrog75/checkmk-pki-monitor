#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Graphing definitions for PKI Monitor plugin.

Defines metrics, graphs, and perfometers for visualizing PKI data.
Compatible with Checkmk 2.3.x (uses legacy metrics API).
"""

from cmk.gui.i18n import _
from cmk.gui.plugins.metrics.utils import (
    metric_info,
    graph_info,
    perfometer_info,
)


# =============================================================================
# Metric Definitions
# =============================================================================

metric_info["ca_cert_days_remaining"] = {
    "title": _("CA Certificate Days Remaining"),
    "unit": "count",
    "color": "26/a",  # Blue
}

metric_info["ca_template_count"] = {
    "title": _("Certificate Templates"),
    "unit": "count",
    "color": "35/a",  # Green
}

metric_info["certs_critical"] = {
    "title": _("Critical Certificates"),
    "unit": "count",
    "color": "14/a",  # Red
}

metric_info["certs_warning"] = {
    "title": _("Warning Certificates"),
    "unit": "count",
    "color": "23/a",  # Yellow
}

metric_info["certs_ok"] = {
    "title": _("OK Certificates"),
    "unit": "count",
    "color": "35/a",  # Green
}

metric_info["certs_total"] = {
    "title": _("Total Certificates"),
    "unit": "count",
    "color": "26/a",  # Blue
}


# =============================================================================
# Graph Definitions
# =============================================================================

graph_info["pki_ca_cert_expiration"] = {
    "title": _("CA Certificate Expiration"),
    "metrics": [
        ("ca_cert_days_remaining", "area"),
    ],
    "range": (0, 365),
}

graph_info["pki_cert_status"] = {
    "title": _("Certificate Expiration Status"),
    "metrics": [
        ("certs_critical", "stack"),
        ("certs_warning", "stack"),
        ("certs_ok", "stack"),
        ("certs_total", "line"),
    ],
}


# =============================================================================
# Perfometer Definitions
# =============================================================================

perfometer_info.append({
    "type": "linear",
    "segments": ["ca_cert_days_remaining"],
    "total": 365.0,
})

perfometer_info.append({
    "type": "stacked",
    "perfometers": [
        {
            "type": "linear",
            "segments": ["certs_critical", "certs_warning", "certs_ok"],
            "total": 100.0,
        },
    ],
})
