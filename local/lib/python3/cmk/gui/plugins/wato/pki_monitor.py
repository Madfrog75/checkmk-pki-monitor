#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WATO Rulesets for PKI Monitor plugin.

These rulesets allow configuration of monitoring thresholds via the Checkmk GUI.
Compatible with Checkmk 2.3.x (uses legacy WATO API).
"""

from cmk.gui.i18n import _
from cmk.gui.valuespec import (
    Dictionary,
    DropdownChoice,
    Integer,
    TextInput,
    Tuple,
)
from cmk.gui.plugins.wato.utils import (
    CheckParameterRulespecWithItem,
    HostRulespec,
    rulespec_registry,
    RulespecGroupCheckParametersApplications,
    RulespecGroupMonitoringAgentsAgentPlugins,
)


# =============================================================================
# Agent Deployment Rule (appears under Setup > Agents > Agent rules)
# =============================================================================

def _valuespec_agent_config_pki_monitor():
    """Valuespec for agent plugin deployment rule."""
    return Dictionary(
        title=_("PKI Monitor (Windows)"),
        help=_(
            "This rule deploys the PKI Monitor agent plugin to Windows hosts. "
            "The plugin queries Microsoft ADCS Certificate Authorities and reports "
            "certificate expiration data back to the Checkmk server."
        ),
        elements=[
            (
                "deploy",
                DropdownChoice(
                    title=_("Deploy PKI Monitor plugin"),
                    choices=[
                        (True, _("Deploy the PKI Monitor agent plugin")),
                        (False, _("Do not deploy")),
                    ],
                    default_value=True,
                ),
            ),
        ],
    )


rulespec_registry.register(
    HostRulespec(
        group=RulespecGroupMonitoringAgentsAgentPlugins,
        name="agent_config:pki_monitor",
        valuespec=_valuespec_agent_config_pki_monitor,
    )
)


# =============================================================================
# Check Parameter Rules (appear under Setup > Services > Service monitoring rules)
# =============================================================================

def _parameter_valuespec_pki_ca_info():
    """Parameter valuespec for PKI CA Info check."""
    return Dictionary(
        title=_("PKI Certificate Authority Monitoring"),
        help=_(
            "Configure thresholds for Certificate Authority monitoring. "
            "This includes CA service status and CA certificate expiration. "
            "Warning threshold should be greater than critical threshold."
        ),
        elements=[
            (
                "ca_cert_warn_days",
                Integer(
                    title=_("Warning threshold for CA certificate expiration (days)"),
                    help=_(
                        "Number of days before the CA's own certificate expires "
                        "to trigger a WARNING state. Must be greater than critical threshold."
                    ),
                    default_value=90,
                    minvalue=1,
                    maxvalue=3650,
                ),
            ),
            (
                "ca_cert_crit_days",
                Integer(
                    title=_("Critical threshold for CA certificate expiration (days)"),
                    help=_(
                        "Number of days before the CA's own certificate expires "
                        "to trigger a CRITICAL state. Must be less than warning threshold."
                    ),
                    default_value=30,
                    minvalue=1,
                    maxvalue=3650,
                ),
            ),
        ],
    )


rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="pki_ca_info",
        group=RulespecGroupCheckParametersApplications,
        item_spec=lambda: TextInput(title=_("CA Name")),
        match_type="dict",
        parameter_valuespec=_parameter_valuespec_pki_ca_info,
        title=lambda: _("PKI Certificate Authority"),
    )
)


def _parameter_valuespec_pki_cert_summary():
    """Parameter valuespec for PKI Certificate Summary check."""
    return Dictionary(
        title=_("PKI Certificate Summary Monitoring"),
        help=_(
            "Configure monitoring for issued certificate expiration summary. "
            "Alerts are based on count of certificates approaching expiration."
        ),
        elements=[
            # Future expansion: add thresholds for certificate counts
        ],
    )


rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="pki_cert_summary",
        group=RulespecGroupCheckParametersApplications,
        item_spec=lambda: TextInput(title=_("CA Name")),
        match_type="dict",
        parameter_valuespec=_parameter_valuespec_pki_cert_summary,
        title=lambda: _("PKI Certificate Summary"),
    )
)


def _parameter_valuespec_pki_expiring_certs():
    """Parameter valuespec for PKI Expiring Certificates check."""
    return Dictionary(
        title=_("PKI Expiring Certificates Monitoring"),
        help=_(
            "Configure thresholds for individual certificate expiration monitoring. "
            "Certificates approaching these thresholds will trigger alerts."
        ),
        elements=[
            (
                "warn_days",
                Integer(
                    title=_("Warning threshold (days until expiration)"),
                    help=_(
                        "Certificates expiring within this many days trigger WARNING. "
                        "Must be greater than critical threshold."
                    ),
                    default_value=30,
                    minvalue=1,
                    maxvalue=3650,
                ),
            ),
            (
                "crit_days",
                Integer(
                    title=_("Critical threshold (days until expiration)"),
                    help=_(
                        "Certificates expiring within this many days trigger CRITICAL. "
                        "Must be less than warning threshold."
                    ),
                    default_value=14,
                    minvalue=1,
                    maxvalue=3650,
                ),
            ),
            (
                "max_display",
                Integer(
                    title=_("Maximum certificates to display"),
                    help=_(
                        "Maximum number of individual certificates to show in check details. "
                        "A warning is shown if more certificates exist."
                    ),
                    default_value=20,
                    minvalue=1,
                    maxvalue=1000,
                ),
            ),
        ],
    )


rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="pki_expiring_certs",
        group=RulespecGroupCheckParametersApplications,
        item_spec=lambda: TextInput(title=_("CA Name")),
        match_type="dict",
        parameter_valuespec=_parameter_valuespec_pki_expiring_certs,
        title=lambda: _("PKI Expiring Certificates"),
    )
)
