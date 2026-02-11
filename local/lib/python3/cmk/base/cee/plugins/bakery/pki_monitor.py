#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bakery plugin for PKI Monitor.

Deploys the PKI Monitor PowerShell agent plugin to Windows hosts
via the Checkmk Agent Bakery (Enterprise Edition).

Compatible with Checkmk 2.3.x.
"""

from pathlib import Path
from typing import Any, Dict

from .bakery_api.v1 import (
    FileGenerator,
    OS,
    Plugin,
    PluginConfig,
    register,
)


def get_pki_monitor_files(conf: Dict[str, Any]) -> FileGenerator:
    """Yield plugin files for deployment to Windows hosts."""
    if conf.get("deploy", True):
        # Deploy the main PowerShell agent plugin
        yield Plugin(
            base_os=OS.WINDOWS,
            source=Path("pki_monitor.ps1"),
        )

        # Generate the default configuration file
        # PluginConfig creates files from lines content (not from source files)
        yield PluginConfig(
            base_os=OS.WINDOWS,
            lines=[
                '<#',
                '.SYNOPSIS',
                '    Configuration file for PKI Monitor Checkmk Agent Plugin',
                '.DESCRIPTION',
                '    Modify these settings to customize the plugin behavior.',
                '#>',
                '',
                '# Override default configuration',
                '$script:Config = @{',
                '    ExpireWarningDays = 30',
                '    ExpireCriticalDays = 14',
                '    MaxCertificates = 1000',
                '    IncludeExpired = $false',
                '    CacheTimeMinutes = 60',
                '    MonitoringPeriodDays = 365',
                '}',
            ],
            target=Path("pki_monitor.cfg.ps1"),
            include_header=False,
        )


register.bakery_plugin(
    name="pki_monitor",
    files_function=get_pki_monitor_files,
)
