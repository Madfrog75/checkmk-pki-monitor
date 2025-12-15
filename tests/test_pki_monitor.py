#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for PKI Monitor Checkmk plugin.

Run with: pytest test_pki_monitor.py -v
"""

import pytest
from typing import Dict, List, Any

# Import the plugin functions
# Note: In actual testing environment, you'd need to set up the import path correctly
# For now, we'll define the parse functions inline for testing

def parse_pki_ca_info(string_table):
    """Parse CA information section."""
    parsed = {}

    for line in string_table:
        if len(line) < 5:
            continue

        ca_name = line[0]

        if ca_name in ("ERROR", "CRITICAL_ERROR"):
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


def parse_pki_cert_summary(string_table):
    """Parse certificate summary section."""
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

            parsed[ca_name] = {
                "critical": critical_count,
                "warning": warning_count,
                "ok": ok_count,
                "total": total_count,
            }
        except (ValueError, IndexError):
            continue

    return parsed


def parse_pki_expiring_certs(string_table):
    """Parse individual expiring certificates section."""
    parsed: Dict[str, List[Dict[str, Any]]] = {}

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


class TestParsePKICAInfo:
    """Tests for parse_pki_ca_info function."""

    def test_parse_single_ca(self):
        """Test parsing a single CA entry."""
        string_table = [
            ["MyCA", "ca.domain.com", "Running", "365", "15"]
        ]
        result = parse_pki_ca_info(string_table)

        assert "MyCA" in result
        assert result["MyCA"]["dns_hostname"] == "ca.domain.com"
        assert result["MyCA"]["service_status"] == "Running"
        assert result["MyCA"]["ca_cert_days_expire"] == 365
        assert result["MyCA"]["template_count"] == 15

    def test_parse_multiple_cas(self):
        """Test parsing multiple CA entries."""
        string_table = [
            ["RootCA", "rootca.domain.com", "Running", "1000", "5"],
            ["SubCA", "subca.domain.com", "Running", "365", "25"],
        ]
        result = parse_pki_ca_info(string_table)

        assert len(result) == 2
        assert "RootCA" in result
        assert "SubCA" in result

    def test_parse_stopped_service(self):
        """Test parsing CA with stopped service."""
        string_table = [
            ["MyCA", "ca.domain.com", "Stopped", "365", "15"]
        ]
        result = parse_pki_ca_info(string_table)

        assert result["MyCA"]["service_status"] == "Stopped"

    def test_parse_error_entry(self):
        """Test parsing error entry."""
        string_table = [
            ["ERROR", "No Certificate Authorities found", "0", "0", "0"]
        ]
        result = parse_pki_ca_info(string_table)

        assert "_error" in result
        assert result["_error"]["type"] == "ERROR"
        assert "No Certificate Authorities" in result["_error"]["message"]

    def test_parse_critical_error(self):
        """Test parsing critical error entry."""
        string_table = [
            ["CRITICAL_ERROR", "Failed to connect", "-1", "-1", "-1"]
        ]
        result = parse_pki_ca_info(string_table)

        assert "_error" in result
        assert result["_error"]["type"] == "CRITICAL_ERROR"

    def test_parse_unknown_days(self):
        """Test parsing entry with unknown days (-1)."""
        string_table = [
            ["MyCA", "ca.domain.com", "Running", "-1", "15"]
        ]
        result = parse_pki_ca_info(string_table)

        assert result["MyCA"]["ca_cert_days_expire"] is None

    def test_parse_incomplete_line(self):
        """Test that incomplete lines are skipped."""
        string_table = [
            ["MyCA", "ca.domain.com"],  # Too short
            ["ValidCA", "ca2.domain.com", "Running", "365", "10"],
        ]
        result = parse_pki_ca_info(string_table)

        assert "MyCA" not in result
        assert "ValidCA" in result


class TestParsePKICertSummary:
    """Tests for parse_pki_cert_summary function."""

    def test_parse_summary(self):
        """Test parsing certificate summary."""
        string_table = [
            ["MyCA", "2", "5", "100", "107"]
        ]
        result = parse_pki_cert_summary(string_table)

        assert "MyCA" in result
        assert result["MyCA"]["critical"] == 2
        assert result["MyCA"]["warning"] == 5
        assert result["MyCA"]["ok"] == 100
        assert result["MyCA"]["total"] == 107

    def test_parse_no_expiring_certs(self):
        """Test parsing with no expiring certificates."""
        string_table = [
            ["MyCA", "0", "0", "50", "50"]
        ]
        result = parse_pki_cert_summary(string_table)

        assert result["MyCA"]["critical"] == 0
        assert result["MyCA"]["warning"] == 0
        assert result["MyCA"]["total"] == 50

    def test_parse_error_marker(self):
        """Test that error markers (-1) are skipped."""
        string_table = [
            ["ErrorCA", "-1", "-1", "-1", "-1"],
            ["ValidCA", "0", "5", "95", "100"],
        ]
        result = parse_pki_cert_summary(string_table)

        assert "ErrorCA" not in result
        assert "ValidCA" in result


class TestParsePKIExpiringCerts:
    """Tests for parse_pki_expiring_certs function."""

    def test_parse_expiring_certs(self):
        """Test parsing individual expiring certificates."""
        string_table = [
            ["MyCA", "webserver.domain.com", "2024-03-15 12:00:00", "14", "WebServer", "ABC123"],
            ["MyCA", "mailserver.domain.com", "2024-03-20 12:00:00", "19", "Exchange", "DEF456"],
        ]
        result = parse_pki_expiring_certs(string_table)

        assert "MyCA" in result
        assert len(result["MyCA"]) == 2
        assert result["MyCA"][0]["common_name"] == "webserver.domain.com"
        assert result["MyCA"][0]["days_until_expire"] == 14
        assert result["MyCA"][1]["thumbprint"] == "DEF456"

    def test_parse_multiple_cas(self):
        """Test parsing certificates from multiple CAs."""
        string_table = [
            ["CA1", "server1.domain.com", "2024-03-15", "14", "Web", "AAA"],
            ["CA2", "server2.domain.com", "2024-03-16", "15", "App", "BBB"],
        ]
        result = parse_pki_expiring_certs(string_table)

        assert "CA1" in result
        assert "CA2" in result
        assert len(result["CA1"]) == 1
        assert len(result["CA2"]) == 1

    def test_parse_error_entry(self):
        """Test that ERROR entries are skipped."""
        string_table = [
            ["MyCA", "ERROR", "Connection failed", "-1", "", ""],
            ["MyCA", "valid.server.com", "2024-03-15", "14", "Web", "ABC"],
        ]
        result = parse_pki_expiring_certs(string_table)

        assert len(result["MyCA"]) == 1
        assert result["MyCA"][0]["common_name"] == "valid.server.com"

    def test_parse_invalid_days(self):
        """Test handling of invalid days value."""
        string_table = [
            ["MyCA", "server.com", "2024-03-15", "invalid", "Web", "ABC"],
        ]
        result = parse_pki_expiring_certs(string_table)

        assert result["MyCA"][0]["days_until_expire"] == -999


class TestCheckLogic:
    """Tests for check function logic."""

    def test_critical_certificate_detection(self):
        """Test that critical certificates are detected correctly."""
        certs = [
            {"common_name": "server1", "days_until_expire": 5},
            {"common_name": "server2", "days_until_expire": 20},
        ]
        warn_days = 30
        crit_days = 14

        critical_certs = [c for c in certs if c["days_until_expire"] <= crit_days]
        warning_certs = [c for c in certs if crit_days < c["days_until_expire"] <= warn_days]

        assert len(critical_certs) == 1
        assert len(warning_certs) == 1
        assert critical_certs[0]["common_name"] == "server1"

    def test_service_status_logic(self):
        """Test service status state determination."""
        def get_state(status):
            if status == "Running":
                return "OK"
            elif status == "Stopped":
                return "CRIT"
            else:
                return "WARN"

        assert get_state("Running") == "OK"
        assert get_state("Stopped") == "CRIT"
        assert get_state("Unknown") == "WARN"
        assert get_state("Starting") == "WARN"


class TestAgentOutputFormat:
    """Tests for expected agent output format."""

    def test_ca_info_section_format(self):
        """Verify CA info section format parsing."""
        # Simulated agent output line
        raw_line = "MyCA;ca.domain.com;Running;365;15"
        parts = raw_line.split(";")

        assert len(parts) == 5
        assert parts[0] == "MyCA"
        assert parts[2] == "Running"
        assert int(parts[3]) == 365

    def test_cert_summary_section_format(self):
        """Verify certificate summary section format."""
        raw_line = "MyCA;2;5;100;107"
        parts = raw_line.split(";")

        assert len(parts) == 5
        total = int(parts[1]) + int(parts[2]) + int(parts[3])
        assert total == int(parts[4])

    def test_expiring_certs_section_format(self):
        """Verify expiring certificates section format."""
        raw_line = "MyCA;server.domain.com;2024-03-15 12:00:00;14;WebServer;ABCD1234"
        parts = raw_line.split(";")

        assert len(parts) == 6
        assert parts[1] == "server.domain.com"
        assert int(parts[3]) == 14


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
