#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Checkmk agent-based check plugin for PKI Certificate Monitoring.
Compatible with Checkmk 2.3.x - uses only confirmed v2 API exports.
"""

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


# =============================================================================
# Section: pki_ca_info
# =============================================================================

def parse_pki_ca_info(string_table):
    parsed = {}
    for line in string_table:
        if len(line) < 5:
            continue
        ca_name = line[0]
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
            continue
    return parsed


agent_section_pki_ca_info = AgentSection(
    name="pki_ca_info",
    parse_function=parse_pki_ca_info,
)


def discover_pki_ca_info(section):
    for ca_name in section:
        if not ca_name.startswith("_"):
            yield Service(item=ca_name)


def check_pki_ca_info(item, params, section):
    if "_error" in section:
        error = section["_error"]
        error_state = State.CRIT if error["type"] in ("CRITICAL_ERROR", "CONFIG_ERROR") else State.WARN
        yield Result(state=error_state, summary="PKI query error: %s" % error["message"])
        return

    if item not in section:
        yield Result(state=State.UNKNOWN, summary="CA not found in agent output")
        return

    ca_info = section[item]

    # Service status
    service_status = ca_info.get("service_status", "Unknown")
    if service_status == "Running":
        yield Result(state=State.OK, summary="Service: %s" % service_status)
    elif service_status in ("Stopped", "Error", "Unknown"):
        yield Result(state=State.CRIT, summary="Service: %s" % service_status)
    else:
        yield Result(state=State.WARN, summary="Service: %s" % service_status)

    # CA certificate expiration
    ca_days = ca_info.get("ca_cert_days_expire")
    if ca_days is not None:
        warn_days = params.get("ca_cert_warn_days", 90)
        crit_days = params.get("ca_cert_crit_days", 30)

        if ca_days <= crit_days:
            yield Result(state=State.CRIT, summary="CA certificate expires in %d days" % ca_days)
        elif ca_days <= warn_days:
            yield Result(state=State.WARN, summary="CA certificate expires in %d days" % ca_days)
        else:
            yield Result(state=State.OK, summary="CA certificate expires in %d days" % ca_days)

        yield Metric("ca_cert_days_remaining", ca_days)
    else:
        yield Result(state=State.WARN, summary="CA certificate expiration unknown")

    # Template count
    template_count = ca_info.get("template_count", 0)
    yield Result(state=State.OK, summary="Templates: %d" % template_count)
    yield Metric("ca_template_count", template_count)

    # Hostname
    yield Result(state=State.OK, notice="Hostname: %s" % ca_info.get("dns_hostname", "Unknown"))


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
# Section: pki_cert_summary
# =============================================================================

def parse_pki_cert_summary(string_table):
    parsed = {}
    for line in string_table:
        if len(line) < 5:
            continue
        ca_name = line[0]
        try:
            critical_count = int(line[1])
            warning_count = int(line[2])
            ok_count = int(line[3])
            total_count = int(line[4])
            if critical_count < 0:
                continue
            truncated = len(line) > 5 and line[5] == "TRUNCATED"
            parsed[ca_name] = {
                "critical": critical_count,
                "warning": warning_count,
                "ok": ok_count,
                "total": total_count,
                "truncated": truncated,
            }
        except (ValueError, IndexError):
            continue
    return parsed


agent_section_pki_cert_summary = AgentSection(
    name="pki_cert_summary",
    parse_function=parse_pki_cert_summary,
)


def discover_pki_cert_summary(section):
    for ca_name in section:
        if not ca_name.startswith("_"):
            yield Service(item=ca_name)


def check_pki_cert_summary(item, params, section):
    if item not in section:
        yield Result(state=State.UNKNOWN, summary="CA not found in agent output")
        return

    data = section[item]
    critical_count = data["critical"]
    warning_count = data["warning"]
    ok_count = data["ok"]
    total_count = data["total"]
    truncated = data.get("truncated", False)

    if critical_count > 0:
        yield Result(state=State.CRIT, summary="%d certificates expiring critically soon" % critical_count)
    elif warning_count > 0:
        yield Result(state=State.WARN, summary="%d certificates expiring soon" % warning_count)
    else:
        yield Result(state=State.OK, summary="All %d certificates OK" % total_count)

    if truncated:
        yield Result(state=State.WARN, summary="Data incomplete: MaxCertificates limit reached")

    yield Result(
        state=State.OK,
        notice="Critical: %d, Warning: %d, OK: %d, Total: %d" % (critical_count, warning_count, ok_count, total_count),
    )

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
# Section: pki_expiring_certs
# =============================================================================

def parse_pki_expiring_certs(string_table):
    parsed = {}
    for line in string_table:
        if len(line) < 6:
            continue
        ca_name = line[0]
        common_name = line[1]
        if common_name == "ERROR":
            continue
        try:
            days_until_expire = int(line[3])
        except ValueError:
            days_until_expire = -999

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
    return parsed


agent_section_pki_expiring_certs = AgentSection(
    name="pki_expiring_certs",
    parse_function=parse_pki_expiring_certs,
)


def discover_pki_expiring_certs(section):
    for ca_name in section:
        if not ca_name.startswith("_"):
            yield Service(item=ca_name)


def check_pki_expiring_certs(item, params, section):
    if item not in section:
        yield Result(state=State.OK, summary="No expiring certificates")
        return

    certs = section[item]
    if not isinstance(certs, list) or not certs:
        yield Result(state=State.OK, summary="No expiring certificates")
        return

    warn_days = params.get("warn_days", 30)
    crit_days = params.get("crit_days", 14)
    max_display = params.get("max_display", 20)

    valid_certs = [c for c in certs if c["days_until_expire"] > -999]
    expired_certs = [c for c in valid_certs if c["days_until_expire"] < 0]
    active_certs = [c for c in valid_certs if c["days_until_expire"] >= 0]
    certs_sorted = sorted(active_certs, key=lambda x: x["days_until_expire"])

    critical_certs = [c for c in certs_sorted if c["days_until_expire"] <= crit_days]
    warning_certs = [c for c in certs_sorted if crit_days < c["days_until_expire"] <= warn_days]

    if expired_certs:
        yield Result(state=State.CRIT, summary="%d certificates already EXPIRED!" % len(expired_certs))
    if critical_certs:
        worst = critical_certs[0]
        yield Result(
            state=State.CRIT,
            summary="%d certs expiring critically! Soonest: %s in %d days" % (
                len(critical_certs), worst["common_name"], worst["days_until_expire"]),
        )
    elif warning_certs:
        worst = warning_certs[0]
        yield Result(
            state=State.WARN,
            summary="%d certs expiring soon. Soonest: %s in %d days" % (
                len(warning_certs), worst["common_name"], worst["days_until_expire"]),
        )
    elif not expired_certs:
        yield Result(state=State.OK, summary="%d certificates monitored" % len(certs))

    for cert in expired_certs[:5]:
        yield Result(
            state=State.CRIT,
            notice="EXPIRED: %s: expired %s (%d days ago), Template: %s" % (
                cert["common_name"], cert["expiration_date"],
                abs(cert["days_until_expire"]), cert["template"]),
        )

    display_certs = certs_sorted[:max_display]
    if len(certs_sorted) > max_display:
        yield Result(
            state=State.OK,
            notice="Showing %d of %d certificates" % (max_display, len(certs_sorted)),
        )

    for cert in display_certs:
        days = cert["days_until_expire"]
        if days <= crit_days:
            state = State.CRIT
        elif days <= warn_days:
            state = State.WARN
        else:
            state = State.OK
        yield Result(
            state=state,
            notice="%s: expires %s (%d days), Template: %s" % (
                cert["common_name"], cert["expiration_date"],
                days, cert["template"]),
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
