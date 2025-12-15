#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Graphing definitions for PKI Monitor plugin.

Defines metrics, graphs, and perfometers for visualizing PKI data.
"""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph, MinimalRange
from cmk.graphing.v1.metrics import (
    Color,
    DecimalNotation,
    Metric,
    StrictPrecision,
    Unit,
)
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer


# =============================================================================
# Metric Definitions
# =============================================================================

metric_ca_cert_days_remaining = Metric(
    name="ca_cert_days_remaining",
    title=Title("CA Certificate Days Remaining"),
    unit=Unit(DecimalNotation("days"), StrictPrecision(0)),
    color=Color.BLUE,
)

metric_ca_template_count = Metric(
    name="ca_template_count",
    title=Title("Certificate Templates"),
    unit=Unit(DecimalNotation("")),
    color=Color.GREEN,
)

metric_certs_critical = Metric(
    name="certs_critical",
    title=Title("Critical Certificates"),
    unit=Unit(DecimalNotation("")),
    color=Color.RED,
)

metric_certs_warning = Metric(
    name="certs_warning",
    title=Title("Warning Certificates"),
    unit=Unit(DecimalNotation("")),
    color=Color.YELLOW,
)

metric_certs_ok = Metric(
    name="certs_ok",
    title=Title("OK Certificates"),
    unit=Unit(DecimalNotation("")),
    color=Color.GREEN,
)

metric_certs_total = Metric(
    name="certs_total",
    title=Title("Total Certificates"),
    unit=Unit(DecimalNotation("")),
    color=Color.BLUE,
)


# =============================================================================
# Graph Definitions
# =============================================================================

graph_ca_cert_expiration = Graph(
    name="pki_ca_cert_expiration",
    title=Title("CA Certificate Expiration"),
    minimal_range=MinimalRange(0, 365),
    compound_lines=["ca_cert_days_remaining"],
)

graph_cert_status = Graph(
    name="pki_cert_status",
    title=Title("Certificate Expiration Status"),
    compound_lines=[
        "certs_critical",
        "certs_warning",
        "certs_ok",
    ],
    simple_lines=["certs_total"],
)


# =============================================================================
# Perfometer Definitions
# =============================================================================

perfometer_ca_cert_days = Perfometer(
    name="pki_ca_cert_days",
    focus_range=FocusRange(Closed(0), Open(365)),
    segments=["ca_cert_days_remaining"],
)

perfometer_cert_status = Perfometer(
    name="pki_cert_status",
    focus_range=FocusRange(Closed(0), Open(100)),
    segments=["certs_critical", "certs_warning", "certs_ok"],
)
