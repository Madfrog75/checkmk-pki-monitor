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
        yield Plugin(
            base_os=OS.WINDOWS,
            source=Path("pki_monitor.ps1"),
        )
        yield PluginConfig(
            base_os=OS.WINDOWS,
            source=Path("pki_monitor.cfg.ps1"),
            target=Path("pki_monitor.cfg.ps1"),
        )


register.bakery_plugin(
    name="pki_monitor",
    files_function=get_pki_monitor_files,
)
