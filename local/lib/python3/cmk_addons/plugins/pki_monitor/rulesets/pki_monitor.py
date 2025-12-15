#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WATO Rulesets for PKI Monitor plugin.

These rulesets allow configuration of monitoring thresholds via the Checkmk GUI.
"""

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DictElement,
    Dictionary,
    Integer,
    SimpleLevels,
    LevelDirection,
    DefaultValue,
    InputHint,
    validators,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, Topic, HostCondition


def _parameter_form_pki_ca_info() -> Dictionary:
    """Parameter form for PKI CA Info check."""
    return Dictionary(
        title=Title("PKI Certificate Authority Monitoring"),
        help_text=Help(
            "Configure thresholds for Certificate Authority monitoring. "
            "This includes CA service status and CA certificate expiration. "
            "Warning threshold should be greater than critical threshold."
        ),
        elements={
            "ca_cert_warn_days": DictElement(
                parameter_form=Integer(
                    title=Title("Warning threshold for CA certificate expiration (days)"),
                    help_text=Help(
                        "Number of days before the CA's own certificate expires "
                        "to trigger a WARNING state. Must be greater than critical threshold."
                    ),
                    prefill=DefaultValue(90),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=3650),),
                ),
            ),
            "ca_cert_crit_days": DictElement(
                parameter_form=Integer(
                    title=Title("Critical threshold for CA certificate expiration (days)"),
                    help_text=Help(
                        "Number of days before the CA's own certificate expires "
                        "to trigger a CRITICAL state. Must be less than warning threshold."
                    ),
                    prefill=DefaultValue(30),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=3650),),
                ),
            ),
        },
    )


rule_spec_pki_ca_info = CheckParameters(
    name="pki_ca_info",
    title=Title("PKI Certificate Authority"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_pki_ca_info,
    condition=HostCondition(),
)


def _parameter_form_pki_cert_summary() -> Dictionary:
    """Parameter form for PKI Certificate Summary check."""
    return Dictionary(
        title=Title("PKI Certificate Summary Monitoring"),
        help_text=Help(
            "Configure monitoring for issued certificate expiration summary. "
            "Alerts are based on count of certificates approaching expiration."
        ),
        elements={
            # Future expansion: add thresholds for certificate counts
        },
    )


rule_spec_pki_cert_summary = CheckParameters(
    name="pki_cert_summary",
    title=Title("PKI Certificate Summary"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_pki_cert_summary,
    condition=HostCondition(),
)


def _parameter_form_pki_expiring_certs() -> Dictionary:
    """Parameter form for PKI Expiring Certificates check."""
    return Dictionary(
        title=Title("PKI Expiring Certificates Monitoring"),
        help_text=Help(
            "Configure thresholds for individual certificate expiration monitoring. "
            "Certificates approaching these thresholds will trigger alerts."
        ),
        elements={
            "warn_days": DictElement(
                parameter_form=Integer(
                    title=Title("Warning threshold (days until expiration)"),
                    help_text=Help(
                        "Certificates expiring within this many days trigger WARNING. "
                        "Must be greater than critical threshold."
                    ),
                    prefill=DefaultValue(30),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=3650),),
                ),
            ),
            "crit_days": DictElement(
                parameter_form=Integer(
                    title=Title("Critical threshold (days until expiration)"),
                    help_text=Help(
                        "Certificates expiring within this many days trigger CRITICAL. "
                        "Must be less than warning threshold."
                    ),
                    prefill=DefaultValue(14),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=3650),),
                ),
            ),
            "max_display": DictElement(
                parameter_form=Integer(
                    title=Title("Maximum certificates to display"),
                    help_text=Help(
                        "Maximum number of individual certificates to show in check details. "
                        "A warning is shown if more certificates exist."
                    ),
                    prefill=DefaultValue(20),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=1000),),
                ),
            ),
        },
    )


rule_spec_pki_expiring_certs = CheckParameters(
    name="pki_expiring_certs",
    title=Title("PKI Expiring Certificates"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_pki_expiring_certs,
    condition=HostCondition(),
)
