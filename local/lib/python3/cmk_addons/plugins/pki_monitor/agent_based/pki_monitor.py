#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Checkmk agent-based check plugin for PKI Certificate Monitoring.

This plugin monitors:
- Certificate Authority health and service status
- CA certificate expiration
- Issued certificate expiration summary
- Individual expiring certificates

Author: PKI Monitor Plugin
Version: 1.0.0
"""

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
    check_levels,
    render,
)


# =============================================================================
# Section: pki_ca_info - Certificate Authority Information
# =============================================================================

def parse_pki_ca_info(string_table: StringTable) -> Dict[str, Dict[str, Any]]:
    """
    Parse CA information section.

    Expected format (semicolon separated):
    CAName;DNSHostName;ServiceStatus;CACertDaysUntilExpire;TemplateCount

    Example:
    MyCA;ca.domain.com;Running;365;15
    """
    parsed = {}
    parse_errors = 0

    for line in string_table:
        if len(line) < 5:
            parse_errors += 1
            continue

        ca_name = line[0]

        # Check for error conditions
        if ca_name in ("ERROR", "CRITICAL_ERROR", "CONFIG_ERROR"):
            parsed["_error"] = {
                "message": line[1] if len(line) > 1 else "Unknown error",
                "type": ca_name,
            }
            continue

        try:
            parsed[ca_name] = {
                "dns_hostname": line[1],
                "service_status": line[2],
                "ca_cert_days_expire": int(line[3]) if line[3] != "-1" else None,
                "template_count": int(line[4]) if line[4] != "-1" else 0,
            }
        except (ValueError, IndexError):
            parse_errors += 1
            continue

    if parse_errors > 0:
        parsed["_parse_errors"] = parse_errors

    return parsed


agent_section_pki_ca_info = AgentSection(
    name="pki_ca_info",
    parse_function=parse_pki_ca_info,
)


def discover_pki_ca_info(section: Dict[str, Dict[str, Any]]) -> DiscoveryResult:
    """Discover Certificate Authorities."""
    for ca_name in section:
        if not ca_name.startswith("_"):
            yield Service(item=ca_name)


def check_pki_ca_info(
    item: str,
    params: Mapping[str, Any],
    section: Dict[str, Dict[str, Any]],
) -> CheckResult:
    """Check Certificate Authority health."""

    # Report parse errors if any
    if "_parse_errors" in section:
        yield Result(
            state=State.WARN,
            notice=f"{section['_parse_errors']} lines could not be parsed from agent output",
        )

    # Check for agent-reported errors
    if "_error" in section:
        error = section["_error"]
        error_state = State.CRIT if error["type"] in ("CRITICAL_ERROR", "CONFIG_ERROR") else State.WARN
        yield Result(
            state=error_state,
            summary=f"PKI query error: {error['message']}",
        )
        return

    if item not in section:
        yield Result(state=State.UNKNOWN, summary="CA not found in agent output")
        return

    ca_info = section[item]

    # Check service status
    service_status = ca_info.get("service_status", "Unknown")
    if service_status == "Running":
        yield Result(state=State.OK, summary=f"Service: {service_status}")
    elif service_status in ("Stopped", "Error"):
        yield Result(state=State.CRIT, summary=f"Service: {service_status}")
    elif service_status == "Unknown":
        yield Result(state=State.CRIT, summary=f"Service: {service_status} - cannot query service")
    elif service_status in ("StartPending", "ContinuePending", "StopPending"):
        yield Result(state=State.WARN, summary=f"Service: {service_status}")
    else:
        yield Result(state=State.WARN, summary=f"Service: {service_status}")

    # Check CA certificate expiration
    ca_days = ca_info.get("ca_cert_days_expire")
    if ca_days is not None:
        warn_days = params.get("ca_cert_warn_days", 90)
        crit_days = params.get("ca_cert_crit_days", 30)

        # Validate threshold ordering
        if warn_days <= crit_days:
            yield Result(
                state=State.WARN,
                notice=f"Invalid thresholds: warn_days ({warn_days}) should be > crit_days ({crit_days})",
            )

        yield from check_levels(
            ca_days,
            metric_name="ca_cert_days_remaining",
            levels_lower=(warn_days, crit_days),
            render_func=lambda x: f"{x:.0f} days",
            label="CA certificate expires in",
        )
        # Note: check_levels already emits the metric, no need for additional Metric yield
    else:
        yield Result(state=State.WARN, summary="CA certificate expiration unknown")

    # Report template count
    template_count = ca_info.get("template_count", 0)
    yield Result(state=State.OK, summary=f"Templates: {template_count}")
    yield Metric("ca_template_count", template_count)

    # Report hostname
    hostname = ca_info.get("dns_hostname", "Unknown")
    yield Result(state=State.OK, notice=f"Hostname: {hostname}")


check_plugin_pki_ca_info = CheckPlugin(
    name="pki_ca_info",
    service_name="PKI CA %s",
    discovery_function=discover_pki_ca_info,
    check_function=check_pki_ca_info,
    check_default_parameters={
        "ca_cert_warn_days": 90,
        "ca_cert_crit_days": 30,
    },
    check_ruleset_name="pki_ca_info",
)


# =============================================================================
# Section: pki_cert_summary - Certificate Expiration Summary
# =============================================================================

def parse_pki_cert_summary(string_table: StringTable) -> Dict[str, Dict[str, Any]]:
    """
    Parse certificate summary section.

    Expected format (semicolon separated):
    CAName;CriticalCount;WarningCount;OKCount;TotalCount[;TRUNCATED]

    Example:
    MyCA;2;5;100;107
    MyCA;2;5;100;107;TRUNCATED
    """
    parsed: Dict[str, Dict[str, Any]] = {}
    parse_errors = 0

    for line in string_table:
        if len(line) < 5:
            parse_errors += 1
            continue

        ca_name = line[0]

        try:
            critical_count = int(line[1])
            warning_count = int(line[2])
            ok_count = int(line[3])
            total_count = int(line[4])

            # Skip error markers
            if critical_count < 0:
                continue

            # Check for TRUNCATED flag (MaxResults was reached)
            truncated = len(line) > 5 and line[5] == "TRUNCATED"

            parsed[ca_name] = {
                "critical": critical_count,
                "warning": warning_count,
                "ok": ok_count,
                "total": total_count,
                "truncated": truncated,
            }
        except (ValueError, IndexError):
            parse_errors += 1
            continue

    if parse_errors > 0:
        parsed["_parse_errors"] = parse_errors  # type: ignore

    return parsed


agent_section_pki_cert_summary = AgentSection(
    name="pki_cert_summary",
    parse_function=parse_pki_cert_summary,
)


def discover_pki_cert_summary(section: Dict[str, Dict[str, int]]) -> DiscoveryResult:
    """Discover CA certificate summaries."""
    for ca_name in section:
        if not ca_name.startswith("_"):
            yield Service(item=ca_name)


def check_pki_cert_summary(
    item: str,
    params: Mapping[str, Any],
    section: Dict[str, Dict[str, Any]],
) -> CheckResult:
    """Check certificate expiration summary."""

    # Report parse errors if any
    if "_parse_errors" in section:
        yield Result(
            state=State.WARN,
            notice=f"{section['_parse_errors']} lines could not be parsed from agent output",
        )

    if item not in section:
        yield Result(state=State.UNKNOWN, summary="CA not found in agent output")
        return

    summary = section[item]

    critical_count = summary["critical"]
    warning_count = summary["warning"]
    ok_count = summary["ok"]
    total_count = summary["total"]
    truncated = summary.get("truncated", False)

    # Determine overall state based on expiring certificates
    if critical_count > 0:
        state = State.CRIT
        summary_text = f"{critical_count} certificates expiring critically soon"
    elif warning_count > 0:
        state = State.WARN
        summary_text = f"{warning_count} certificates expiring soon"
    else:
        state = State.OK
        summary_text = f"All {total_count} certificates OK"

    yield Result(state=state, summary=summary_text)

    # Warn if data was truncated due to MaxResults limit
    if truncated:
        yield Result(
            state=State.WARN,
            summary="Data incomplete: MaxCertificates limit reached",
        )

    # Detailed breakdown
    yield Result(
        state=State.OK,
        notice=f"Critical: {critical_count}, Warning: {warning_count}, OK: {ok_count}, Total: {total_count}",
    )

    # Metrics
    yield Metric("certs_critical", critical_count)
    yield Metric("certs_warning", warning_count)
    yield Metric("certs_ok", ok_count)
    yield Metric("certs_total", total_count)


check_plugin_pki_cert_summary = CheckPlugin(
    name="pki_cert_summary",
    service_name="PKI Certificates %s",
    discovery_function=discover_pki_cert_summary,
    check_function=check_pki_cert_summary,
    check_default_parameters={},
    check_ruleset_name="pki_cert_summary",
)


# =============================================================================
# Section: pki_expiring_certs - Individual Expiring Certificates
# =============================================================================

def parse_pki_expiring_certs(string_table: StringTable) -> Dict[str, Any]:
    """
    Parse individual expiring certificates section.

    Expected format (semicolon separated):
    CAName;CommonName;ExpirationDate;DaysUntilExpire;Template;Thumbprint

    Example:
    MyCA;webserver.domain.com;2024-03-15 12:00:00;14;WebServer;ABC123
    """
    parsed: Dict[str, Any] = {}
    parse_errors = 0

    for line in string_table:
        if len(line) < 6:
            parse_errors += 1
            continue

        ca_name = line[0]
        common_name = line[1]

        # Skip error entries
        if common_name == "ERROR":
            continue

        try:
            days_until_expire = int(line[3])
        except ValueError:
            days_until_expire = -999
            parse_errors += 1

        cert_info = {
            "common_name": common_name,
            "expiration_date": line[2],
            "days_until_expire": days_until_expire,
            "template": line[4] if len(line) > 4 else "Unknown",
            "thumbprint": line[5] if len(line) > 5 else "Unknown",
        }

        if ca_name not in parsed:
            parsed[ca_name] = []
        parsed[ca_name].append(cert_info)

    if parse_errors > 0:
        parsed["_parse_errors"] = parse_errors

    return parsed


agent_section_pki_expiring_certs = AgentSection(
    name="pki_expiring_certs",
    parse_function=parse_pki_expiring_certs,
)


def discover_pki_expiring_certs(section: Dict[str, List[Dict[str, Any]]]) -> DiscoveryResult:
    """Discover expiring certificate services per CA."""
    for ca_name in section:
        if not ca_name.startswith("_"):
            yield Service(item=ca_name)


def check_pki_expiring_certs(
    item: str,
    params: Mapping[str, Any],
    section: Dict[str, Any],
) -> CheckResult:
    """Check individual expiring certificates."""

    # Report parse errors if any
    if "_parse_errors" in section:
        yield Result(
            state=State.WARN,
            notice=f"{section['_parse_errors']} lines could not be parsed from agent output",
        )

    if item not in section:
        yield Result(state=State.OK, summary="No expiring certificates")
        return

    certs = section[item]

    # Handle case where certs is the parse_errors value (int)
    if not isinstance(certs, list):
        yield Result(state=State.OK, summary="No expiring certificates")
        return

    if not certs:
        yield Result(state=State.OK, summary="No expiring certificates")
        return

    warn_days = params.get("warn_days", 30)
    crit_days = params.get("crit_days", 14)
    max_display = params.get("max_display", 20)

    # Validate threshold ordering
    if warn_days <= crit_days:
        yield Result(
            state=State.WARN,
            notice=f"Invalid thresholds: warn_days ({warn_days}) should be > crit_days ({crit_days})",
        )

    # Filter out parse errors (-999) and separate expired certs from valid ones
    valid_certs = [c for c in certs if c["days_until_expire"] > -999]
    expired_certs = [c for c in valid_certs if c["days_until_expire"] < 0]
    active_certs = [c for c in valid_certs if c["days_until_expire"] >= 0]

    # Sort by days until expiration (soonest first)
    certs_sorted = sorted(active_certs, key=lambda x: x["days_until_expire"])

    critical_certs = []
    warning_certs = []

    for cert in certs_sorted:
        days = cert["days_until_expire"]
        if days <= crit_days:
            critical_certs.append(cert)
        elif days <= warn_days:
            warning_certs.append(cert)

    # Summary
    if expired_certs:
        yield Result(
            state=State.CRIT,
            summary=f"{len(expired_certs)} certificates already EXPIRED!",
        )
    if critical_certs:
        worst_cert = critical_certs[0]
        yield Result(
            state=State.CRIT,
            summary=f"{len(critical_certs)} certs expiring critically! Soonest: {worst_cert['common_name']} in {worst_cert['days_until_expire']} days",
        )
    elif warning_certs:
        worst_cert = warning_certs[0]
        yield Result(
            state=State.WARN,
            summary=f"{len(warning_certs)} certs expiring soon. Soonest: {worst_cert['common_name']} in {worst_cert['days_until_expire']} days",
        )
    elif not expired_certs:
        yield Result(state=State.OK, summary=f"{len(certs)} certificates monitored")

    # Report expired certificates first
    for cert in expired_certs[:5]:  # Show up to 5 expired certs
        template = cert['template']
        template_display = template[:27] + "..." if len(template) > 30 else template
        # Include full template name if truncated
        full_template_info = f" (full: {template})" if len(template) > 30 else ""
        yield Result(
            state=State.CRIT,
            notice=f"EXPIRED: {cert['common_name']}: expired {cert['expiration_date']} ({abs(cert['days_until_expire'])} days ago), Template: {template_display}{full_template_info}",
        )

    # List expiring certificates in details with truncation warning
    display_certs = certs_sorted[:max_display]
    if len(certs_sorted) > max_display:
        yield Result(
            state=State.OK,
            notice=f"Showing {max_display} of {len(certs_sorted)} certificates (increase max_display parameter to see more)",
        )

    for cert in display_certs:
        days = cert["days_until_expire"]
        if days <= crit_days:
            state = State.CRIT
        elif days <= warn_days:
            state = State.WARN
        else:
            state = State.OK

        template = cert['template']
        template_display = template[:27] + "..." if len(template) > 30 else template
        # Include full template name if truncated
        full_template_info = f" (full: {template})" if len(template) > 30 else ""
        yield Result(
            state=state,
            notice=f"{cert['common_name']}: expires {cert['expiration_date']} ({days} days), Template: {template_display}{full_template_info}",
        )


check_plugin_pki_expiring_certs = CheckPlugin(
    name="pki_expiring_certs",
    service_name="PKI Expiring Certs %s",
    discovery_function=discover_pki_expiring_certs,
    check_function=check_pki_expiring_certs,
    check_default_parameters={
        "warn_days": 30,
        "crit_days": 14,
        "max_display": 20,
    },
    check_ruleset_name="pki_expiring_certs",
)
