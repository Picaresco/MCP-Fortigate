#!/usr/bin/env python3
"""
Local read-only MCP server for Fortigate over SSH.

The server is intentionally conservative: it exposes only read-only tools and
validates every user-supplied command against an allowlist before opening SSH.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import paramiko
from mcp.server.fastmcp import FastMCP
from pydantic import Field


mcp = FastMCP("fortigate_mcp")
logging.getLogger("paramiko").setLevel(logging.WARNING)

DEFAULT_CONFIG_PATH = Path(__file__).with_name("fortigate.config.json")
SNAPSHOT_DIR = Path(__file__).with_name("snapshots")
MAX_COMMAND_LENGTH = 240
MAX_OUTPUT_CHARS = 60000
PROMPT_PATTERN = re.compile(r"(?m)^[^\r\n]+ [#$] $")
MORE_MARKER = "--More--"
SENSITIVE_CONFIG_PATTERN = re.compile(
    r'(?im)^(\s*set\s+(?:psksecret|password|passwd|secret|comments|private-key|token|key)\s+).*$'
)

READONLY_COMMANDS: dict[str, str] = {
    "system_status": "get system status",
    "system_performance": "get system performance status",
    "interfaces": "get system interface",
    "system_interfaces_config": "show system interface",
    "hardware_nic": "get hardware nic",
    "routing_table": "get router info routing-table all",
    "routing_database": "get router info routing-table database",
    "policy_routes": "show router policy",
    "bgp_summary": "get router info bgp summary",
    "ospf_neighbor": "get router info ospf neighbor",
    "arp": "get system arp",
    "dns": "get system dns",
    "ntp": "get system ntp",
    "ha_status": "get system ha status",
    "sessions_summary": "get system session status",
    "firewall_policies": "show firewall policy",
    "address_objects": "show firewall address",
    "address_groups": "show firewall addrgrp",
    "service_objects": "show firewall service custom",
    "service_groups": "show firewall service group",
    "vip_objects": "show firewall vip",
    "vip_groups": "show firewall vipgrp",
    "ippools": "show firewall ippool",
    "central_snat": "show firewall central-snat-map",
    "local_in_policy": "show firewall local-in-policy",
    "proxy_policy": "show firewall proxy-policy",
    "access_proxy": "show firewall access-proxy",
    "dos_policy": "show firewall DoS-policy",
    "traffic_shaper": "show firewall shaper traffic-shaper",
    "per_ip_shaper": "show firewall shaper per-ip-shaper",
    "utm_av": "show antivirus profile",
    "utm_webfilter": "show webfilter profile",
    "utm_ips": "show ips sensor",
    "utm_appctrl": "show application list",
    "utm_ssl_ssh": "show firewall ssl-ssh-profile",
    "static_routes": "show router static",
    "sdwan_health_check": "diagnose sys sdwan health-check",
    "sdwan_service": "diagnose sys sdwan service",
    "sdwan_config": "show system sdwan",
    "system_admin": "show system admin",
    "system_accprofile": "show system accprofile",
    "system_global": "show system global",
    "ssl_vpn_settings": "show vpn ssl settings",
    "ssl_vpn_portals": "show vpn ssl web portal",
    "user_local": "show user local",
    "user_groups": "show user group",
    "ipsec_tunnel_summary": "get vpn ipsec tunnel summary",
    "ipsec_phase1_interface": "show vpn ipsec phase1-interface",
    "ipsec_phase1": "show vpn ipsec phase1",
    "ipsec_phase2_interface": "show vpn ipsec phase2-interface",
    "ipsec_phase2": "show vpn ipsec phase2",
    "ssl_vpn_monitor": "get vpn ssl monitor",
}

AUDIT_COMMAND_KEYS = [
    "system_status",
    "system_performance",
    "ha_status",
    "sessions_summary",
    "system_global",
    "interfaces",
    "system_interfaces_config",
    "routing_table",
    "static_routes",
    "dns",
    "ntp",
    "firewall_policies",
    "address_objects",
    "service_objects",
    "vip_objects",
    "ssl_vpn_settings",
    "ssl_vpn_portals",
    "ssl_vpn_monitor",
    "user_local",
    "user_groups",
    "ipsec_tunnel_summary",
    "ipsec_phase1_interface",
    "ipsec_phase2_interface",
]

ALLOWED_EXACT_COMMANDS = set(READONLY_COMMANDS.values())
ALLOWED_REGEXES = [
    re.compile(r"^get\s+system\s+(status|performance\s+status|interface|arp|dns|ntp|ha\s+status|session\s+status)$"),
    re.compile(r"^get\s+hardware\s+nic(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^get\s+router\s+info\s+routing-table\s+(all|database|details|static|connected|kernel|ospf|bgp)$"),
    re.compile(r"^get\s+router\s+info\s+(bgp\s+summary|ospf\s+neighbor)$"),
    re.compile(r"^show\s+system\s+(interface|admin|global|accprofile)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+firewall\s+(policy|address|addrgrp|service\s+custom|service\s+group|vip|vipgrp|ippool|central-snat-map|local-in-policy|proxy-policy|access-proxy|dos-policy)(?:\s+\d+)?$"),
    re.compile(r"^show\s+firewall\s+shaper\s+(traffic-shaper|per-ip-shaper)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+firewall\s+ssl-ssh-profile(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+router\s+(static|policy)(?:\s+\d+)?$"),
    re.compile(r"^show\s+(antivirus\s+profile|webfilter\s+profile|ips\s+sensor|application\s+list)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+system\s+sdwan$"),
    re.compile(r"^diagnose\s+sys\s+sdwan\s+(health-check|service)$"),
    re.compile(r"^get\s+vpn\s+ipsec\s+tunnel\s+summary$"),
    re.compile(r"^get\s+vpn\s+ssl\s+monitor$"),
    re.compile(r"^show\s+vpn\s+ssl\s+(settings|web\s+portal)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+vpn\s+ipsec\s+(phase1-interface|phase1|phase2-interface|phase2)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+endpoint-control\s+fctems(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+firewall\s+(access-proxy|proxy-policy)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+user\s+(local|group)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^diagnose\s+sys\s+(top-summary|session\s+stat)$"),
    re.compile(
        r"^diagnose\s+sys\s+session\s+(list|filter\s+(clear|src\s+\d{1,3}(?:\.\d{1,3}){3}|dst\s+\d{1,3}(?:\.\d{1,3}){3}|sport\s+(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])|dport\s+(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])|proto\s+(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])))$"
    ),
    re.compile(r"^diagnose\s+netlink\s+interface\s+list(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^diagnose\s+ip\s+(arp\s+list|route\s+list)$"),
    re.compile(
        r"^diagnose\s+sniffer\s+packet\s+(any|[A-Za-z0-9_.:-]+)\s+'[A-Za-z0-9_.:/*()\-\s]+'\s+[1-4]\s+(?:[1-9]|1\d|20)\s+a$"
    ),
    re.compile(
        r"^execute\s+log\s+filter\s+(category\s+(event|traffic|utm)|field\s+(type|subtype|action|user|srcip|dstip|srcport|dstport|status|level|vd|logid|policyid|service|proto|trandisp|srcintf|dstintf|sentbyte|rcvdbyte)\s+[A-Za-z0-9_.:@*-]+|view-lines\s+(?:[1-9]\d?|[1-4]\d\d|500))$"
    ),
    re.compile(r"^execute\s+log\s+display$"),
]

SAFE_EXECUTE_ROOTS = {("execute", "log")}

BLOCKED_WORDS = {
    "config",
    "edit",
    "set",
    "unset",
    "append",
    "select",
    "delete",
    "purge",
    "end",
    "next",
    "abort",
    "execute",
    "exec",
    "reboot",
    "shutdown",
    "restore",
    "factoryreset",
    "format",
    "debug",
    "diag",  # require the full "diagnose" form and explicit allowlist entry
}

SHELL_META_PATTERN = re.compile(r"[;&|`$<>\n\r]")
LOG_ACCESS_ERROR_PATTERN = re.compile(
    r"(?im)(permission denied|not permitted|not allowed|command fail|unknown action|invalid command|command parse error)"
)


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


class LogCategory(str, Enum):
    """Fortigate log category accepted by limited log search tools."""

    EVENT = "event"
    TRAFFIC = "traffic"
    UTM = "utm"


class LogField(str, Enum):
    """Fortigate log fields accepted by limited log search tools."""

    TYPE = "type"
    SUBTYPE = "subtype"
    ACTION = "action"
    USER = "user"
    SRCIP = "srcip"
    DSTIP = "dstip"
    STATUS = "status"
    LEVEL = "level"
    VD = "vd"
    LOGID = "logid"
    POLICYID = "policyid"
    SERVICE = "service"
    PROTO = "proto"
    SRCPORT = "srcport"
    DSTPORT = "dstport"
    TRANDISP = "trandisp"
    SRCINTF = "srcintf"
    DSTINTF = "dstintf"
    SENTBYTE = "sentbyte"
    RCVDBYTE = "rcvdbyte"


CommandParam = Annotated[
    str,
    Field(
        description="Read-only Fortigate CLI command. Allowed examples: 'get system status', 'show firewall policy'.",
        min_length=3,
        max_length=MAX_COMMAND_LENGTH,
    ),
]
ResponseFormatParam = Annotated[
    ResponseFormat,
    Field(description="Output format: markdown for human-readable output, json for structured output."),
]
IpAddressParam = Annotated[
    str,
    Field(description="IPv4 address to search in firewall address objects and policies.", min_length=7, max_length=45),
]
OptionalIpAddressParam = Annotated[
    str | None,
    Field(default=None, description="Optional IPv4 address filter.", min_length=7, max_length=45),
]
PortParam = Annotated[
    int | None,
    Field(default=None, description="Optional TCP/UDP port filter, 1-65535.", ge=1, le=65535),
]
ProtocolParam = Annotated[
    int | None,
    Field(default=None, description="Optional IP protocol number, for example 6 for TCP or 17 for UDP.", ge=0, le=255),
]
RequiredProtocolParam = Annotated[
    int,
    Field(description="IP protocol number, for example 6 for TCP, 17 for UDP, or 1 for ICMP.", ge=0, le=255),
]
LogCategoryParam = Annotated[
    LogCategory,
    Field(description="Fortigate log category to search. Use 'event' for admin, VPN, system, and authentication events."),
]
LogFieldParam = Annotated[
    LogField | None,
    Field(default=None, description="Optional Fortigate log field to filter, for example srcip, dstip, user, action, subtype, status, or level."),
]
LogValueParam = Annotated[
    str | None,
    Field(
        default=None,
        description="Value for the selected log field. Spaces and shell metacharacters are not allowed.",
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9_.:@*-]+$",
    ),
]
LogViewLinesParam = Annotated[
    int,
    Field(description="Maximum log lines to display. Kept bounded to reduce Fortigate log-search impact.", ge=1, le=500),
]
SnapshotFileParam = Annotated[
    str,
    Field(
        description="Snapshot filename previously created under the local snapshots directory.",
        min_length=5,
        max_length=160,
        pattern=r"^[A-Za-z0-9_.-]+\.json$",
    ),
]
SnifferInterfaceParam = Annotated[
    str,
    Field(
        default="any",
        description="Fortigate interface to sniff. Use 'any' unless you need a specific interface.",
        min_length=1,
        max_length=40,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    ),
]
SnifferFilterParam = Annotated[
    str,
    Field(
        description="Required BPF-style packet filter, for example 'host 10.0.0.10 and port 443'. Keep it narrow.",
        min_length=7,
        max_length=120,
        pattern=r"^[A-Za-z0-9_.:/*() \-]+$",
    ),
]
SnifferVerbosityParam = Annotated[
    int,
    Field(default=4, description="Fortigate sniffer verbosity, limited to 1-4.", ge=1, le=4),
]
SnifferCountParam = Annotated[
    int,
    Field(default=10, description="Maximum packets to capture, limited to 1-20.", ge=1, le=20),
]
SnapshotLabelParam = Annotated[
    str | None,
    Field(
        default=None,
        description="Optional snapshot label. Only letters, numbers, dot, dash, and underscore are kept.",
        max_length=80,
    ),
]


@dataclass(frozen=True)
class FortigateConfig:
    """SSH connection settings loaded from fortigate.config.json."""

    host: str
    port: int
    username: str
    password: str
    timeout: int = 15
    banner_timeout: int = 15
    auth_timeout: int = 15
    look_for_keys: bool = False
    allow_agent: bool = False
    disabled_algorithms: dict[str, Any] | None = None


def load_config() -> FortigateConfig:
    """Load Fortigate SSH settings from JSON config."""

    raw_path = os.environ.get("FORTIGATE_MCP_CONFIG")
    config_path = Path(raw_path).expanduser() if raw_path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        raise FileNotFoundError(
            f"Missing config file: {config_path}. Copy fortigate.config.example.json to "
            "fortigate.config.json and fill in host, username, and password."
        )

    with config_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    section = data.get("fortigate")
    if not isinstance(section, dict):
        raise ValueError("Config must contain an object at key 'fortigate'.")

    required = ["host", "username", "password"]
    missing = [name for name in required if not section.get(name)]
    if missing:
        raise ValueError(f"Missing required Fortigate config field(s): {', '.join(missing)}.")

    return FortigateConfig(
        host=str(section["host"]),
        port=int(section.get("port", 22)),
        username=str(section["username"]),
        password=str(section["password"]),
        timeout=int(section.get("timeout", 15)),
        banner_timeout=int(section.get("banner_timeout", section.get("timeout", 15))),
        auth_timeout=int(section.get("auth_timeout", section.get("timeout", 15))),
        look_for_keys=bool(section.get("look_for_keys", False)),
        allow_agent=bool(section.get("allow_agent", False)),
        disabled_algorithms=section.get("disabled_algorithms") or None,
    )


def normalize_command(command: str) -> str:
    """Collapse whitespace and remove harmless trailing semicolons/spaces."""

    return " ".join(command.strip().rstrip(";").split())


def validate_readonly_command(command: str) -> str:
    """Validate a Fortigate CLI command against read-only allowlist rules."""

    normalized = normalize_command(command)
    lowered = normalized.lower()

    if not normalized:
        raise ValueError("Command cannot be empty.")
    if len(normalized) > MAX_COMMAND_LENGTH:
        raise ValueError(f"Command is too long. Maximum length is {MAX_COMMAND_LENGTH} characters.")
    if SHELL_META_PATTERN.search(normalized):
        raise ValueError("Command contains shell metacharacters or line breaks, which are not allowed.")

    try:
        tokens = [token.lower() for token in shlex.split(normalized)]
    except ValueError as exc:
        raise ValueError(f"Command could not be parsed safely: {exc}") from exc

    if not tokens:
        raise ValueError("Command cannot be empty.")

    allowed_safe_execute = len(tokens) >= 2 and (tokens[0], tokens[1]) in SAFE_EXECUTE_ROOTS and any(
        pattern.fullmatch(lowered) for pattern in ALLOWED_REGEXES
    )

    blocked = sorted(BLOCKED_WORDS.intersection(tokens))
    if allowed_safe_execute:
        blocked = [token for token in blocked if token != "execute"]
    if blocked:
        raise ValueError(
            "Command is blocked because it contains potentially modifying or unsafe token(s): "
            f"{', '.join(blocked)}."
        )

    if tokens[0] not in {"get", "show", "diagnose", "execute"}:
        raise ValueError("Only explicitly allowlisted 'get', 'show', limited 'diagnose', and log-read 'execute' commands are allowed.")

    if lowered in ALLOWED_EXACT_COMMANDS:
        return normalized

    if any(pattern.fullmatch(lowered) for pattern in ALLOWED_REGEXES):
        return normalized

    raise ValueError(
        "Command is not in the read-only allowlist. Use fortigate_list_allowed_commands to see supported commands."
    )


def run_ssh_command_sync(command: str) -> dict[str, Any]:
    """Execute one validated CLI command over SSH and return structured output."""

    config = load_config()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=config.host,
            port=config.port,
            username=config.username,
            password=config.password,
            timeout=config.timeout,
            banner_timeout=config.banner_timeout,
            auth_timeout=config.auth_timeout,
            look_for_keys=config.look_for_keys,
            allow_agent=config.allow_agent,
            disabled_algorithms=config.disabled_algorithms,
        )

        stdout_text = run_fortigate_shell_command(client, command, config.timeout)
        stderr_text = ""

        return {
            "command": command,
            "exit_status": 0,
            "stdout": trim_output(stdout_text),
            "stderr": trim_output(stderr_text),
            "truncated": len(stdout_text) > MAX_OUTPUT_CHARS or len(stderr_text) > MAX_OUTPUT_CHARS,
        }
    finally:
        client.close()


def run_fortigate_shell_command(client: paramiko.SSHClient, command: str, timeout: int) -> str:
    """Run a command in an interactive Fortigate shell and advance CLI paging."""

    channel = client.invoke_shell(width=240, height=1000)
    channel.settimeout(1.0)
    deadline = time.monotonic() + timeout

    drain_until_prompt(channel, deadline)
    channel.send(command + "\n")

    chunks: list[str] = []
    while time.monotonic() < deadline:
        if not channel.recv_ready():
            time.sleep(0.05)
            continue

        chunk = channel.recv(65535).decode("utf-8", errors="replace")
        chunks.append(chunk)

        if MORE_MARKER in chunk:
            channel.send(" ")

        output = "".join(chunks)
        if PROMPT_PATTERN.search(output):
            return clean_fortigate_output(output, command)

    raise TimeoutError(f"Timed out waiting for Fortigate command output after {timeout} seconds.")


def drain_until_prompt(channel: paramiko.Channel, deadline: float) -> None:
    """Read Fortigate login banner and initial prompt before sending commands."""

    buffer = ""
    while time.monotonic() < deadline:
        if not channel.recv_ready():
            time.sleep(0.05)
            continue

        buffer += channel.recv(65535).decode("utf-8", errors="replace")
        if PROMPT_PATTERN.search(buffer):
            return

    raise TimeoutError("Timed out waiting for initial Fortigate SSH prompt.")


def clean_fortigate_output(output: str, command: str) -> str:
    """Remove echoed command, prompt lines, and Fortigate pager control text."""

    cleaned = output.replace("\r", "")
    cleaned = cleaned.replace(MORE_MARKER, "")
    cleaned = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", cleaned)
    cleaned = re.sub(r"(?m)^[^\n]+ [#$] $", "", cleaned)
    cleaned = SENSITIVE_CONFIG_PATTERN.sub(r"\1[redacted]", cleaned)

    lines = cleaned.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].strip() == command:
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines)


async def run_ssh_command(command: str) -> dict[str, Any]:
    """Run blocking Paramiko SSH work in a worker thread."""

    return await asyncio.to_thread(run_ssh_command_sync, command)


def run_ssh_command_sequence_sync(commands: list[str]) -> list[dict[str, Any]]:
    """Execute validated Fortigate commands in one SSH shell session."""

    config = load_config()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=config.host,
            port=config.port,
            username=config.username,
            password=config.password,
            timeout=config.timeout,
            banner_timeout=config.banner_timeout,
            auth_timeout=config.auth_timeout,
            look_for_keys=config.look_for_keys,
            allow_agent=config.allow_agent,
            disabled_algorithms=config.disabled_algorithms,
        )

        channel = client.invoke_shell(width=240, height=1000)
        channel.settimeout(1.0)
        drain_until_prompt(channel, time.monotonic() + config.timeout)

        results = []
        for command in commands:
            deadline = time.monotonic() + config.timeout
            channel.send(command + "\n")
            chunks: list[str] = []
            while time.monotonic() < deadline:
                if not channel.recv_ready():
                    time.sleep(0.05)
                    continue
                chunk = channel.recv(65535).decode("utf-8", errors="replace")
                chunks.append(chunk)
                if MORE_MARKER in chunk:
                    channel.send(" ")
                output = "".join(chunks)
                if PROMPT_PATTERN.search(output):
                    cleaned = clean_fortigate_output(output, command)
                    results.append(
                        {
                            "command": command,
                            "exit_status": 0,
                            "stdout": trim_output(cleaned),
                            "stderr": "",
                            "truncated": len(cleaned) > MAX_OUTPUT_CHARS,
                        }
                    )
                    break
            else:
                raise TimeoutError(f"Timed out waiting for Fortigate command output after {config.timeout} seconds.")

        return results
    finally:
        client.close()


async def run_ssh_command_sequence(commands: list[str]) -> list[dict[str, Any]]:
    """Run a blocking Fortigate command sequence in a worker thread."""

    safe_commands = [validate_readonly_command(command) for command in commands]
    return await asyncio.to_thread(run_ssh_command_sequence_sync, safe_commands)


def trim_output(value: str) -> str:
    """Trim very large Fortigate outputs to keep MCP context manageable."""

    if len(value) <= MAX_OUTPUT_CHARS:
        return value
    return value[:MAX_OUTPUT_CHARS] + "\n\n[output truncated by fortigate_mcp]"


def format_result(result: dict[str, Any], response_format: ResponseFormat) -> str:
    """Format command result as markdown or JSON."""

    if response_format == ResponseFormat.JSON:
        return json.dumps(result, indent=2, ensure_ascii=False)

    lines = [
        f"# Fortigate Command Result",
        "",
        f"- Command: `{result['command']}`",
        f"- Exit status: `{result['exit_status']}`",
        f"- Output truncated: `{str(result['truncated']).lower()}`",
        "",
        "## stdout",
        "```text",
        result["stdout"].strip() or "(empty)",
        "```",
    ]

    if result.get("stderr"):
        lines.extend(["", "## stderr", "```text", result["stderr"].strip(), "```"])

    return "\n".join(lines)


def format_error(error: Exception) -> str:
    """Return an actionable error without leaking internals."""

    return (
        f"Error: {type(error).__name__}: {error}\n\n"
        "Check that fortigate.config.json exists, SSH is reachable, and the Fortigate user has read-only permissions."
    )


async def execute_readonly(command: str, response_format: ResponseFormat) -> str:
    """Validate and execute a read-only Fortigate command."""

    try:
        safe_command = validate_readonly_command(command)
        result = await run_ssh_command(safe_command)
        return format_result(result, response_format)
    except Exception as exc:
        return format_error(exc)


def add_finding(
    findings: list[dict[str, str]],
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
) -> None:
    """Append a normalized audit finding."""

    findings.append(
        {
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation,
        }
    )


def parse_config_blocks(config_text: str) -> dict[str, str]:
    """Parse simple Fortigate 'edit "name"...next' blocks."""

    blocks: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []

    for line in config_text.splitlines():
        edit_match = re.match(r'\s*edit\s+"?([^"]+?)"?\s*$', line)
        if edit_match:
            current_name = edit_match.group(1)
            current_lines = [line]
            continue

        if current_name is not None:
            current_lines.append(line)
            if line.strip() == "next":
                blocks[current_name] = "\n".join(current_lines)
                current_name = None
                current_lines = []

    return blocks


def quoted_values(block: str, field: str) -> list[str]:
    """Extract quoted Fortigate values from a 'set <field> ...' line."""

    match = re.search(rf"(?m)^\s*set\s+{re.escape(field)}\s+(.+)$", block)
    if not match:
        return []
    values = re.findall(r'"([^"]+)"', match.group(1))
    if values:
        return values
    return match.group(1).split()


def build_audit_findings(outputs: dict[str, str]) -> list[dict[str, str]]:
    """Create pragmatic read-only audit findings from Fortigate CLI outputs."""

    findings: list[dict[str, str]] = []
    system_status = outputs.get("system_status", "")
    performance = outputs.get("system_performance", "")
    interfaces_config = outputs.get("system_interfaces_config", "")
    firewall_policy = outputs.get("firewall_policies", "")
    ssl_settings = outputs.get("ssl_vpn_settings", "")
    ssl_monitor = outputs.get("ssl_vpn_monitor", "")
    ipsec_summary = outputs.get("ipsec_tunnel_summary", "")
    system_admin = outputs.get("system_admin", "")
    vip_objects = outputs.get("vip_objects", "")

    version_match = re.search(r"Version:\s+(.+?)\s+v(\d+)\.(\d+)\.(\d+),build(\d+)", system_status)
    if version_match:
        version_label = version_match.group(1).strip()
        major, minor, patch = [int(version_match.group(i)) for i in range(2, 5)]
        if (major, minor, patch) <= (7, 4, 0):
            add_finding(
                findings,
                "High",
                "Firmware 7.4.0 en produccion",
                f"{version_label} v{major}.{minor}.{patch} build {version_match.group(5)}",
                "Planificar upgrade siguiendo el upgrade path oficial de Fortinet para la rama 7.4.",
            )

    memory_match = re.search(r"Memory:\s+\d+k total,\s+\d+k used \(([\d.]+)%\)", performance)
    if memory_match:
        memory_pct = float(memory_match.group(1))
        if memory_pct >= 80:
            severity = "High"
        elif memory_pct >= 70:
            severity = "Medium"
        else:
            severity = ""
        if severity:
            add_finding(
                findings,
                severity,
                "Uso de memoria elevado",
                f"Memoria usada: {memory_pct}%",
                "Revisar sesiones, UTM activado y procesos si el valor se mantiene alto.",
            )

    cpu_match = re.search(r"CPU states:.*?(\d+)% idle", performance)
    if cpu_match and int(cpu_match.group(1)) < 20:
        add_finding(
            findings,
            "Medium",
            "CPU con poco margen",
            f"Idle actual: {cpu_match.group(1)}%",
            "Revisar procesos y trafico si se repite durante varios muestreos.",
        )

    interface_blocks = parse_config_blocks(interfaces_config)
    risky_admin_interfaces = []
    for name, block in interface_blocks.items():
        allowaccess = quoted_values(block, "allowaccess")
        if not allowaccess:
            continue
        risky_protocols = sorted(set(allowaccess).intersection({"http", "telnet"}))
        if risky_protocols:
            risky_admin_interfaces.append(f"{name}: {', '.join(risky_protocols)}")
    if risky_admin_interfaces:
        add_finding(
            findings,
            "High",
            "Servicios de administracion inseguros en interfaces",
            "; ".join(risky_admin_interfaces[:10]),
            "Eliminar HTTP/Telnet y usar solo HTTPS/SSH restringido por trusted hosts o red de gestion.",
        )

    admin_blocks = parse_config_blocks(system_admin)
    admins_without_trusthost = []
    super_admins = []
    for name, block in admin_blocks.items():
        if 'set accprofile "super_admin"' in block:
            super_admins.append(name)
        if "set trusthost" not in block:
            admins_without_trusthost.append(name)
    if admins_without_trusthost:
        add_finding(
            findings,
            "High",
            "Administradores sin trusted hosts",
            ", ".join(admins_without_trusthost[:12]),
            "Restringir cada administrador a IPs/redes de gestion conocidas.",
        )
    if len(super_admins) > 2:
        add_finding(
            findings,
            "Medium",
            "Varios administradores con super_admin",
            ", ".join(super_admins[:12]),
            "Aplicar minimo privilegio y reservar super_admin para cuentas estrictamente necesarias.",
        )

    policy_blocks = parse_config_blocks(firewall_policy)
    broad_policies = []
    for policy_id, block in policy_blocks.items():
        if 'set action accept' not in block:
            continue
        srcaddr = set(quoted_values(block, "srcaddr"))
        dstaddr = set(quoted_values(block, "dstaddr"))
        service = set(quoted_values(block, "service"))
        if "all" in {value.lower() for value in srcaddr} and "all" in {value.lower() for value in dstaddr}:
            broad_policies.append(f"policy {policy_id}: srcaddr all, dstaddr all")
        elif "ALL" in service or "all" in {value.lower() for value in service}:
            broad_policies.append(f"policy {policy_id}: service ALL")
    if broad_policies:
        add_finding(
            findings,
            "Medium",
            "Politicas firewall amplias",
            "; ".join(broad_policies[:15]),
            "Revisar si siguen siendo necesarias, limitar origen/destino/servicio y activar logging donde aplique.",
        )

    vip_count = len(parse_config_blocks(vip_objects))
    if vip_count:
        add_finding(
            findings,
            "Informational",
            "VIPs/publicaciones NAT detectadas",
            f"{vip_count} objetos VIP configurados",
            "Revisar que cada publicacion tenga propietario, justificacion, restriccion de origen y logging.",
        )

    if re.search(r"(?m)^\s*set\s+source-address\s+\"?all\"?", ssl_settings):
        add_finding(
            findings,
            "High",
            "SSL-VPN permite origen all",
            'show vpn ssl settings contiene source-address "all"',
            "Restringir origenes permitidos cuando sea viable y exigir MFA.",
        )

    ssl_users_without_mfa = []
    for line in ssl_monitor.splitlines():
        if re.match(r"\s*\d+\s+", line) and line.rstrip().endswith("\t0"):
            parts = [part.strip() for part in line.split("\t") if part.strip()]
            if len(parts) >= 2:
                ssl_users_without_mfa.append(parts[1])
    if ssl_users_without_mfa:
        add_finding(
            findings,
            "High",
            "Usuarios SSL-VPN conectados sin MFA visible",
            ", ".join(ssl_users_without_mfa[:12]),
            "Exigir FortiToken/RADIUS MFA para todos los grupos SSL-VPN.",
        )

    down_tunnels = []
    tunnel_errors = []
    for line in ipsec_summary.splitlines():
        match = re.search(
            r"'([^']+)'.*selectors\(total,up\):\s+(\d+)/(\d+).*rx\(pkt,err\):\s+\d+/(\d+).*tx\(pkt,err\):\s+\d+/(\d+)",
            line,
        )
        if not match:
            continue
        name, total, up, rx_err, tx_err = match.groups()
        if int(up) < int(total):
            down_tunnels.append(f"{name}: {up}/{total}")
        if int(rx_err) or int(tx_err):
            tunnel_errors.append(f"{name}: rx_err {rx_err}, tx_err {tx_err}")
    if down_tunnels:
        add_finding(
            findings,
            "Medium",
            "Tuneles IPsec con selectores caidos",
            "; ".join(down_tunnels),
            "Validar si son tuneles bajo demanda o incidencias reales con las entidades externas.",
        )
    if tunnel_errors:
        add_finding(
            findings,
            "Low",
            "Errores en tuneles IPsec",
            "; ".join(tunnel_errors),
            "Revisar contadores historicos y repetir medicion para confirmar si siguen aumentando.",
        )

    if "Log hard disk: Not available" in system_status:
        add_finding(
            findings,
            "Medium",
            "Sin disco local de logs",
            "System status: Log hard disk Not available",
            "Confirmar envio a FortiAnalyzer/syslog y logging habilitado en politicas relevantes.",
        )

    if not findings:
        add_finding(
            findings,
            "Informational",
            "Sin hallazgos automaticos",
            "La auditoria automatica no encontro patrones de riesgo basicos.",
            "Revisar manualmente las salidas completas si se requiere auditoria exhaustiva.",
        )

    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    return sorted(findings, key=lambda item: severity_rank.get(item["severity"], 99))


def format_audit_report(results: list[dict[str, Any]], response_format: ResponseFormat) -> str:
    """Format audit command outputs and findings."""

    outputs = {result["key"]: result.get("stdout", "") for result in results}
    findings = build_audit_findings(outputs)
    payload = {
        "findings": findings,
        "commands": [
            {
                "key": result["key"],
                "command": result["command"],
                "exit_status": result["exit_status"],
                "truncated": result["truncated"],
                "stderr": result.get("stderr", ""),
            }
            for result in results
        ],
    }

    if response_format == ResponseFormat.JSON:
        payload["raw_outputs"] = outputs
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# Fortigate Read-only Audit", ""]
    for severity in ["Critical", "High", "Medium", "Low", "Informational"]:
        severity_findings = [finding for finding in findings if finding["severity"] == severity]
        if not severity_findings:
            continue
        lines.extend([f"## {severity}", ""])
        for finding in severity_findings:
            lines.extend(
                [
                    f"### {finding['title']}",
                    f"- Evidence: {finding['evidence']}",
                    f"- Recommendation: {finding['recommendation']}",
                    "",
                ]
            )

    lines.extend(["## Commands Run", ""])
    for result in results:
        status = "ok" if result["exit_status"] == 0 else "error"
        lines.append(f"- `{result['command']}`: {status}")
    return "\n".join(lines)


async def collect_command_keys(keys: list[str]) -> list[dict[str, Any]]:
    """Run predefined read-only commands by key and return keyed results."""

    results: list[dict[str, Any]] = []
    for key in keys:
        command = READONLY_COMMANDS[key]
        try:
            result = await run_ssh_command(validate_readonly_command(command))
            result["key"] = key
            results.append(result)
        except Exception as exc:
            results.append(
                {
                    "key": key,
                    "command": command,
                    "exit_status": 1,
                    "stdout": "",
                    "stderr": str(exc),
                    "truncated": False,
                }
            )
    return results


def get_set_line(block: str, field: str) -> str | None:
    """Return a Fortigate 'set <field> ...' value without the field name."""

    match = re.search(rf"(?m)^\s*set\s+{re.escape(field)}\s+(.+)$", block)
    return match.group(1).strip() if match else None


def parse_firewall_addresses(address_config: str) -> dict[str, dict[str, Any]]:
    """Parse common firewall address object forms."""

    objects: dict[str, dict[str, Any]] = {}
    for name, block in parse_config_blocks(address_config).items():
        obj: dict[str, Any] = {"name": name, "raw": block}
        subnet = get_set_line(block, "subnet")
        if subnet:
            parts = subnet.split()
            if len(parts) >= 2:
                obj["subnet"] = f"{parts[0]} {parts[1]}"
                try:
                    obj["network"] = str(ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False))
                except ValueError:
                    pass
        for field in ["start-ip", "end-ip", "fqdn", "type"]:
            value = get_set_line(block, field)
            if value:
                obj[field.replace("-", "_")] = value.strip('"')
        objects[name] = obj
    return objects


def parse_firewall_addrgrps(group_config: str) -> dict[str, list[str]]:
    """Parse firewall address groups from show firewall addrgrp output."""

    groups: dict[str, list[str]] = {}
    for name, block in parse_config_blocks(group_config).items():
        groups[name] = quoted_values(block, "member")
    return groups


def object_matches_ip(obj: dict[str, Any], ip: ipaddress._BaseAddress) -> bool:
    """Return True if a parsed address object contains an IP."""

    if "network" in obj:
        try:
            return ip in ipaddress.ip_network(obj["network"], strict=False)
        except ValueError:
            return False

    start_ip = obj.get("start_ip")
    end_ip = obj.get("end_ip")
    if start_ip and end_ip:
        try:
            return ipaddress.ip_address(start_ip) <= ip <= ipaddress.ip_address(end_ip)
        except ValueError:
            return False

    return False


def parse_policy_rows(policy_config: str) -> list[dict[str, Any]]:
    """Parse firewall policy blocks into compact row dictionaries."""

    rows: list[dict[str, Any]] = []
    for policy_id, block in parse_config_blocks(policy_config).items():
        rows.append(
            {
                "id": policy_id,
                "name": (get_set_line(block, "name") or "").strip('"'),
                "status": get_set_line(block, "status") or "enable",
                "srcintf": quoted_values(block, "srcintf"),
                "dstintf": quoted_values(block, "dstintf"),
                "srcaddr": quoted_values(block, "srcaddr"),
                "dstaddr": quoted_values(block, "dstaddr"),
                "service": quoted_values(block, "service"),
                "action": get_set_line(block, "action") or "",
                "nat": get_set_line(block, "nat") or "disable",
                "logtraffic": get_set_line(block, "logtraffic") or "",
                "raw": block,
            }
        )
    return rows


def parse_vip_rows(vip_config: str) -> list[dict[str, Any]]:
    """Parse VIP objects into compact row dictionaries."""

    rows: list[dict[str, Any]] = []
    for name, block in parse_config_blocks(vip_config).items():
        rows.append(
            {
                "name": name,
                "extip": (get_set_line(block, "extip") or "").strip('"'),
                "mappedip": " ".join(quoted_values(block, "mappedip")),
                "extintf": " ".join(quoted_values(block, "extintf")),
                "portforward": get_set_line(block, "portforward") or "disable",
                "protocol": get_set_line(block, "protocol") or "",
                "extport": get_set_line(block, "extport") or "",
                "mappedport": get_set_line(block, "mappedport") or "",
            }
        )
    return rows


def parse_local_in_policy_rows(policy_config: str) -> list[dict[str, Any]]:
    """Parse local-in policy blocks into compact row dictionaries."""

    rows: list[dict[str, Any]] = []
    for policy_id, block in parse_config_blocks(policy_config).items():
        rows.append(
            {
                "id": policy_id,
                "status": get_set_line(block, "status") or "enable",
                "intf": quoted_values(block, "intf"),
                "srcaddr": quoted_values(block, "srcaddr"),
                "dstaddr": quoted_values(block, "dstaddr"),
                "service": quoted_values(block, "service"),
                "action": get_set_line(block, "action") or "",
                "schedule": " ".join(quoted_values(block, "schedule")),
                "raw": block,
            }
        )
    return rows


def parse_service_custom(service_config: str) -> dict[str, dict[str, Any]]:
    """Parse custom firewall service objects used by policy flow matching."""

    services: dict[str, dict[str, Any]] = {}
    for name, block in parse_config_blocks(service_config).items():
        services[name] = {
            "name": name,
            "protocol": (get_set_line(block, "protocol") or "").strip('"').upper(),
            "tcp_portrange": get_set_line(block, "tcp-portrange") or "",
            "udp_portrange": get_set_line(block, "udp-portrange") or "",
            "sctp_portrange": get_set_line(block, "sctp-portrange") or "",
            "protocol_number": get_set_line(block, "protocol-number") or "",
            "raw": block,
        }
    return services


def parse_service_groups(group_config: str) -> dict[str, list[str]]:
    """Parse firewall service groups from show firewall service group output."""

    groups: dict[str, list[str]] = {}
    for name, block in parse_config_blocks(group_config).items():
        groups[name] = quoted_values(block, "member")
    return groups


def format_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Build a markdown table."""

    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(value).replace("\n", " ") for value in row) + " |")
    return "\n".join(lines)


def parse_ipv4(value: str, label: str = "IP address") -> ipaddress.IPv4Address:
    """Parse and validate an IPv4 address for CLI filters."""

    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv4 address.") from exc
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise ValueError(f"{label} must be an IPv4 address.")
    return parsed


def parse_routing_table_routes(routing_table: str) -> list[dict[str, Any]]:
    """Parse common Fortigate routing-table lines into route dictionaries."""

    routes: list[dict[str, Any]] = []
    route_pattern = re.compile(
        r"^\s*(?P<code>[A-Z*]+)\s+"
        r"(?P<prefix>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})"
        r"(?:\s+\[(?P<distance>\d+)/(?P<metric>\d+)\])?"
        r"(?:\s+via\s+(?P<gateway>\d{1,3}(?:\.\d{1,3}){3}),\s*(?P<via_interface>[A-Za-z0-9_.:-]+))?"
        r"(?:\s+is directly connected,\s*(?P<direct_interface>[A-Za-z0-9_.:-]+))?",
    )
    for line in routing_table.splitlines():
        match = route_pattern.match(line)
        if not match:
            continue
        try:
            network = ipaddress.ip_network(match.group("prefix"), strict=False)
        except ValueError:
            continue
        routes.append(
            {
                "code": match.group("code"),
                "network": str(network),
                "prefix_length": network.prefixlen,
                "gateway": match.group("gateway") or "",
                "interface": match.group("via_interface") or match.group("direct_interface") or "",
                "distance": match.group("distance") or "",
                "metric": match.group("metric") or "",
                "raw": line.strip(),
                "_network": network,
            }
        )
    return routes


def find_best_route(routes: list[dict[str, Any]], target_ip: ipaddress.IPv4Address) -> dict[str, Any] | None:
    """Return the longest-prefix route matching an IPv4 address."""

    matches = [route for route in routes if target_ip in route["_network"]]
    if not matches:
        return None
    return max(
        matches,
        key=lambda route: (
            route["prefix_length"],
            -int(route["distance"] or 999),
            -int(route["metric"] or 999999),
        ),
    )


def public_route(route: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a route dictionary without private parser-only fields."""

    if not route:
        return None
    return {key: value for key, value in route.items() if not key.startswith("_")}


def address_ref_matches_ip(
    name: str,
    ip: ipaddress.IPv4Address,
    addresses: dict[str, dict[str, Any]],
    groups: dict[str, list[str]],
    seen: set[str] | None = None,
) -> bool:
    """Return True if an address object/group reference can contain an IP."""

    if name.lower() == "all":
        return True
    if name in addresses:
        return object_matches_ip(addresses[name], ip)
    if name not in groups:
        return False
    seen = seen or set()
    if name in seen:
        return False
    seen.add(name)
    return any(address_ref_matches_ip(member, ip, addresses, groups, seen) for member in groups[name])


def policy_address_side_matches(
    refs: list[str],
    ip: ipaddress.IPv4Address,
    addresses: dict[str, dict[str, Any]],
    groups: dict[str, list[str]],
) -> tuple[bool, list[str]]:
    """Return whether policy address refs match an IP and which refs matched."""

    matches = [ref for ref in refs if address_ref_matches_ip(ref, ip, addresses, groups)]
    return bool(matches), matches


def port_in_ranges(port: int, ranges: str) -> bool:
    """Return True if a port is contained in a Fortigate service port range string."""

    for item in ranges.replace(",", " ").split():
        part = item.split(":", 1)[0]
        if "-" in part:
            start, end = part.split("-", 1)
        else:
            start = end = part
        try:
            if int(start) <= port <= int(end):
                return True
        except ValueError:
            continue
    return False


BUILTIN_SERVICES: dict[str, dict[str, Any]] = {
    "ALL": {"protocols": "any", "ports": "any"},
    "ALL_TCP": {"protocols": {6}, "ports": "any"},
    "ALL_UDP": {"protocols": {17}, "ports": "any"},
    "HTTP": {"protocols": {6}, "ports": {80}},
    "HTTPS": {"protocols": {6}, "ports": {443}},
    "SSH": {"protocols": {6}, "ports": {22}},
    "TELNET": {"protocols": {6}, "ports": {23}},
    "FTP": {"protocols": {6}, "ports": {20, 21}},
    "DNS": {"protocols": {6, 17}, "ports": {53}},
    "PING": {"protocols": {1}, "ports": "any"},
    "RDP": {"protocols": {6}, "ports": {3389}},
    "NTP": {"protocols": {17}, "ports": {123}},
    "SMTP": {"protocols": {6}, "ports": {25}},
    "SMTPS": {"protocols": {6}, "ports": {465}},
    "IMAP": {"protocols": {6}, "ports": {143}},
    "IMAPS": {"protocols": {6}, "ports": {993}},
    "POP3": {"protocols": {6}, "ports": {110}},
    "POP3S": {"protocols": {6}, "ports": {995}},
    "LDAP": {"protocols": {6, 17}, "ports": {389}},
    "LDAPS": {"protocols": {6}, "ports": {636}},
    "SNMP": {"protocols": {17}, "ports": {161}},
}


def builtin_service_matches(name: str, protocol: int, port: int | None) -> bool:
    """Return True if a common built-in service matches protocol/port."""

    service = BUILTIN_SERVICES.get(name.upper())
    if not service:
        return False
    protocols = service["protocols"]
    ports = service["ports"]
    if protocols != "any" and protocol not in protocols:
        return False
    return ports == "any" or port in ports


def custom_service_matches(service: dict[str, Any], protocol: int, port: int | None) -> bool:
    """Return True if a custom service matches protocol/port."""

    protocol_number = service.get("protocol_number")
    if protocol_number:
        try:
            return int(protocol_number) == protocol
        except ValueError:
            pass

    if protocol == 6 and service.get("tcp_portrange"):
        return port is not None and port_in_ranges(port, service["tcp_portrange"])
    if protocol == 17 and service.get("udp_portrange"):
        return port is not None and port_in_ranges(port, service["udp_portrange"])
    if protocol == 132 and service.get("sctp_portrange"):
        return port is not None and port_in_ranges(port, service["sctp_portrange"])
    return False


def service_ref_matches_flow(
    name: str,
    protocol: int,
    port: int | None,
    services: dict[str, dict[str, Any]],
    groups: dict[str, list[str]],
    seen: set[str] | None = None,
) -> bool:
    """Return True if a service object/group reference matches protocol/port."""

    if builtin_service_matches(name, protocol, port):
        return True
    if name in services:
        return custom_service_matches(services[name], protocol, port)
    if name not in groups:
        return False
    seen = seen or set()
    if name in seen:
        return False
    seen.add(name)
    return any(service_ref_matches_flow(member, protocol, port, services, groups, seen) for member in groups[name])


def policy_service_matches(
    refs: list[str],
    protocol: int,
    port: int | None,
    services: dict[str, dict[str, Any]],
    groups: dict[str, list[str]],
) -> tuple[bool, list[str]]:
    """Return whether policy service refs match a flow and which refs matched."""

    matches = [ref for ref in refs if service_ref_matches_flow(ref, protocol, port, services, groups)]
    return bool(matches), matches


def interface_refs_match(refs: list[str], expected: str) -> bool:
    """Return True if policy interface refs are compatible with an expected interface."""

    if not expected:
        return True
    lowered = {ref.lower() for ref in refs}
    return expected.lower() in lowered or "any" in lowered


def parse_hardware_nic(output: str) -> dict[str, str]:
    """Parse key/value fields from get hardware nic <port>."""

    fields = {}
    wanted = {
        "Admin",
        "netdev status",
        "Speed",
        "Duplex",
        "link_status",
        "Host Tx dropped",
        "Rx Pkts",
        "Tx Pkts",
    }
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in wanted:
            fields[key] = value.strip()
    return fields


def safe_snapshot_label(label: str | None) -> str:
    """Return a filesystem-safe label."""

    if not label:
        return "snapshot"
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", label.strip())
    return cleaned.strip("._-") or "snapshot"


def resolve_snapshot_file(filename: str) -> Path:
    """Resolve a snapshot filename inside SNAPSHOT_DIR without allowing path traversal."""

    candidate = SNAPSHOT_DIR / filename
    resolved_dir = SNAPSHOT_DIR.resolve()
    resolved_file = candidate.resolve()
    if resolved_file.parent != resolved_dir:
        raise ValueError("Snapshot file must be directly inside the snapshots directory.")
    if not resolved_file.exists():
        raise FileNotFoundError(f"Snapshot not found: {filename}")
    return resolved_file


def load_snapshot_outputs(filename: str) -> dict[str, str]:
    """Load command outputs from a local snapshot export."""

    path = resolve_snapshot_file(filename)
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    outputs: dict[str, str] = {}
    for item in data.get("commands", []):
        key = item.get("key") or item.get("command")
        if key:
            outputs[key] = item.get("stdout", "")
    return outputs


def parse_ssl_vpn_session_rows(ssl_monitor: str) -> list[dict[str, str]]:
    """Parse the SSL-VPN sessions table from 'get vpn ssl monitor'."""

    rows: list[dict[str, str]] = []
    in_sessions = False
    for line in ssl_monitor.splitlines():
        if line.startswith("SSL-VPN sessions:"):
            in_sessions = True
            continue
        if not in_sessions or not re.match(r"\s*\d+\s+", line):
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        if re.match(r"\d{1,3}(?:\.\d{1,3}){3}", parts[2]):
            index, user, source_ip, duration, io_bytes, tunnel_ip = parts[:6]
            group = ""
        else:
            index, user, group, source_ip, duration, io_bytes, tunnel_ip = parts[:7]

        rows.append(
            {
                "index": index,
                "user": user,
                "group": group,
                "source_ip": source_ip,
                "duration": duration,
                "io_bytes": io_bytes,
                "tunnel_ip": tunnel_ip,
            }
        )
    return rows


def parse_session_destinations(session_list: str, source_ip: str) -> list[dict[str, Any]]:
    """Extract destination IP/port/protocol tuples from diagnose session output."""

    destinations: dict[tuple[str, str, str], dict[str, Any]] = {}
    source_re = re.escape(source_ip)
    flow_pattern = re.compile(
        rf"{source_re}:(\d+)->(\d{{1,3}}(?:\.\d{{1,3}}){{3}}):(\d+).*?\b(proto=(\d+))?"
    )

    for line in session_list.splitlines():
        if source_ip not in line or "->" not in line:
            continue
        match = flow_pattern.search(line)
        if not match:
            continue
        src_port, dst_ip, dst_port, _proto_text, proto_num = match.groups()
        key = (dst_ip, dst_port, proto_num or "")
        entry = destinations.setdefault(
            key,
            {
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": proto_num or "",
                "session_count": 0,
                "example_source_ports": [],
            },
        )
        entry["session_count"] += 1
        if len(entry["example_source_ports"]) < 5:
            entry["example_source_ports"].append(src_port)

    return sorted(
        destinations.values(),
        key=lambda item: (-int(item["session_count"]), item["destination_ip"], item["destination_port"]),
    )


def summarize_session_trace(session_list: str) -> dict[str, Any]:
    """Extract compact evidence from 'diagnose sys session list' output."""

    session_count = len(re.findall(r"(?m)^\s*session info:", session_list))
    policy_ids = sorted(set(re.findall(r"\bpolicy_id=(\d+)", session_list)), key=int)
    states = sorted(set(re.findall(r"(?m)^\s*state=([^\r\n]+)", session_list)))
    hooks = sorted(set(re.findall(r"(?m)^\s*hook=([^\r\n]+)", session_list)))
    evidence_lines = []
    for line in session_list.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        if any(token in cleaned for token in ["->", "policy_id=", "state=", "hook=", "session info:"]):
            evidence_lines.append(cleaned)
        if len(evidence_lines) >= 80:
            break
    return {
        "session_count": session_count,
        "policy_ids": policy_ids,
        "states": states[:20],
        "hooks": hooks[:20],
        "evidence_lines": evidence_lines,
    }


def parse_fortigate_log_lines(log_output: str) -> list[dict[str, str]]:
    """Parse Fortigate key=value log lines into dictionaries."""

    events: list[dict[str, str]] = []
    pattern = re.compile(r'(\w+)=(".*?"|\S+)')
    for line in log_output.splitlines():
        if not re.match(r"\d+:\s+date=", line):
            continue
        event = {}
        for key, value in pattern.findall(line):
            event[key] = value.strip('"')
        events.append(event)
    return events


def detect_log_access_error(results: list[dict[str, Any]]) -> list[str]:
    """Return CLI error lines that indicate event logs could not be read."""

    error_lines: list[str] = []
    for result in results:
        output = "\n".join([result.get("stdout", ""), result.get("stderr", "")])
        for line in output.splitlines():
            cleaned = line.strip()
            if cleaned and LOG_ACCESS_ERROR_PATTERN.search(cleaned):
                error_lines.append(cleaned)
    return error_lines[:10]


def summarize_auth_events(events: list[dict[str, str]]) -> dict[str, Any]:
    """Summarize authentication-related failures and noisy sources."""

    auth_failures = []
    ipsec_failures = []
    successful_admin_logins = []

    for event in events:
        text = " ".join(
            [
                event.get("logdesc", ""),
                event.get("msg", ""),
                event.get("reason", ""),
                event.get("status", ""),
                event.get("action", ""),
            ]
        ).lower()
        subtype = event.get("subtype", "")
        status = event.get("status", "").lower()

        if event.get("action") == "login" and status == "success" and subtype == "system":
            successful_admin_logins.append(event)
            continue

        is_auth_failure = any(term in text for term in ["login failed", "failed login", "auth", "authentication"]) and (
            "fail" in text or status in {"failed", "failure"}
        )
        if is_auth_failure:
            auth_failures.append(event)
            continue

        if subtype == "vpn" and status in {"failure", "negotiate_error"}:
            ipsec_failures.append(event)

    by_source: dict[str, int] = {}
    by_user: dict[str, int] = {}
    for event in auth_failures:
        src = event.get("srcip") or event.get("remip") or "unknown"
        user = event.get("user") or event.get("xauthuser") or "unknown"
        by_source[src] = by_source.get(src, 0) + 1
        by_user[user] = by_user.get(user, 0) + 1

    ipsec_by_peer: dict[str, int] = {}
    for event in ipsec_failures:
        peer = event.get("remip", "unknown")
        ipsec_by_peer[peer] = ipsec_by_peer.get(peer, 0) + 1

    return {
        "auth_failure_count": len(auth_failures),
        "auth_failures_by_source": dict(sorted(by_source.items(), key=lambda item: item[1], reverse=True)),
        "auth_failures_by_user": dict(sorted(by_user.items(), key=lambda item: item[1], reverse=True)),
        "sample_auth_failures": auth_failures[:20],
        "ipsec_failure_count": len(ipsec_failures),
        "ipsec_failures_by_peer": dict(sorted(ipsec_by_peer.items(), key=lambda item: item[1], reverse=True)),
        "successful_admin_logins": successful_admin_logins[:20],
    }


def event_is_error_like(event: dict[str, str]) -> bool:
    """Return True for log events that look operationally relevant for errors."""

    level = event.get("level", "").lower()
    status = event.get("status", "").lower()
    action = event.get("action", "").lower()
    text = " ".join(
        [
            event.get("logdesc", ""),
            event.get("msg", ""),
            event.get("reason", ""),
            event.get("error", ""),
            event.get("status", ""),
            event.get("action", ""),
        ]
    ).lower()
    return (
        level in {"warning", "error", "critical", "alert", "emergency"}
        or status in {"failed", "failure", "deny", "denied", "negotiate_error", "timeout"}
        or action in {"deny", "blocked", "server-rst", "client-rst"}
        or any(term in text for term in ["fail", "error", "denied", "timeout", "negotiate_error"])
    )


def summarize_events_by_field(events: list[dict[str, str]], field: str) -> dict[str, int]:
    """Return descending counts for a log field."""

    counts: dict[str, int] = {}
    for event in events:
        value = event.get(field) or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))


def candidate_policies_for_flow(
    policy_config: str,
    address_config: str,
    address_group_config: str,
    service_config: str,
    service_group_config: str,
    routing_table: str,
    source_ip: ipaddress.IPv4Address,
    destination_ip: ipaddress.IPv4Address,
    protocol: int,
    dst_port: int | None,
) -> dict[str, Any]:
    """Return route context and static policy candidates for a flow."""

    addresses = parse_firewall_addresses(address_config)
    address_groups = parse_firewall_addrgrps(address_group_config)
    services = parse_service_custom(service_config)
    service_groups = parse_service_groups(service_group_config)
    routes = parse_routing_table_routes(routing_table)
    source_route = find_best_route(routes, source_ip)
    destination_route = find_best_route(routes, destination_ip)
    destination_interface = destination_route["interface"] if destination_route else ""

    candidates = []
    for policy in parse_policy_rows(policy_config):
        if not interface_refs_match(policy["dstintf"], destination_interface):
            continue
        src_match, src_refs = policy_address_side_matches(policy["srcaddr"], source_ip, addresses, address_groups)
        dst_match, dst_refs = policy_address_side_matches(policy["dstaddr"], destination_ip, addresses, address_groups)
        svc_match, svc_refs = policy_service_matches(policy["service"], protocol, dst_port, services, service_groups)
        if src_match and dst_match and svc_match:
            candidates.append(
                {
                    "id": policy["id"],
                    "name": policy["name"],
                    "status": policy["status"],
                    "action": policy["action"],
                    "nat": policy["nat"],
                    "logtraffic": policy["logtraffic"],
                    "srcintf": policy["srcintf"],
                    "dstintf": policy["dstintf"],
                    "matched_srcaddr": src_refs,
                    "matched_dstaddr": dst_refs,
                    "matched_service": svc_refs,
                    "ippool": get_set_line(policy["raw"], "ippool") or "disable",
                    "poolname": quoted_values(policy["raw"], "poolname"),
                }
            )

    return {
        "source_route": public_route(source_route),
        "destination_route": public_route(destination_route),
        "candidate_policies": candidates,
    }


@mcp.tool(
    name="fortigate_list_allowed_commands",
    annotations={
        "title": "List Allowed Fortigate Commands",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def fortigate_list_allowed_commands() -> str:
    """List predefined read-only Fortigate commands supported by this MCP server.

    Returns:
        str: JSON-formatted mapping from logical command names to exact Fortigate CLI commands.
    """

    return json.dumps(
        {
            "predefined_commands": READONLY_COMMANDS,
            "manual_command_policy": {
                "allowed_roots": ["get", "show", "diagnose", "execute"],
                "diagnose_scope": "Only explicitly allowlisted diagnostic read commands.",
                "execute_scope": "Only bounded 'execute log filter ...' and 'execute log display' commands. Destructive log operations such as delete, delete-all, backup, and flush-cache are not allowed.",
                "blocked_tokens": sorted(BLOCKED_WORDS),
            },
        },
        indent=2,
    )


@mcp.tool(
    name="fortigate_run_readonly_command",
    annotations={
        "title": "Run Read-only Fortigate Command",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_run_readonly_command(
    command: CommandParam,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run a manually supplied Fortigate CLI command if it passes the read-only allowlist.

    Args:
        command (str): Fortigate CLI command. Must match the read-only allowlist.
        response_format (ResponseFormat): markdown or json output.

    Returns:
        str: Command output, exit status, stderr if present, and truncation metadata.
    """

    return await execute_readonly(command, response_format)


@mcp.tool(
    name="fortigate_get_system_status",
    annotations={
        "title": "Get Fortigate System Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_system_status(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run 'get system status' on the Fortigate and return version/license/uptime details."""

    return await execute_readonly(READONLY_COMMANDS["system_status"], response_format)


@mcp.tool(
    name="fortigate_get_interfaces",
    annotations={
        "title": "Get Fortigate Interfaces",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_interfaces(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run 'get system interface' on the Fortigate and return interface state/configuration."""

    return await execute_readonly(READONLY_COMMANDS["interfaces"], response_format)


@mcp.tool(
    name="fortigate_get_routes",
    annotations={
        "title": "Get Fortigate Routes",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_routes(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run 'get router info routing-table all' on the Fortigate and return the routing table."""

    return await execute_readonly(READONLY_COMMANDS["routing_table"], response_format)


@mcp.tool(
    name="fortigate_lookup_route_for_ip",
    annotations={
        "title": "Lookup Fortigate Route For IP",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_lookup_route_for_ip(
    ip: IpAddressParam,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Find the best matching route for an IPv4 destination using the current Fortigate routing table.

    Use this for troubleshooting reachability, asymmetric routing, VPN routing, and policy analysis.
    The tool only runs `get router info routing-table all`; longest-prefix matching is done locally.
    """

    target_ip = parse_ipv4(ip, "Destination IP")
    result = await run_ssh_command(validate_readonly_command(READONLY_COMMANDS["routing_table"]))
    routes = parse_routing_table_routes(result.get("stdout", ""))
    best_route = find_best_route(routes, target_ip)
    matching_routes = sorted(
        [route for route in routes if target_ip in route["_network"]],
        key=lambda route: (-route["prefix_length"], int(route["distance"] or 999), int(route["metric"] or 999999)),
    )
    payload = {
        "ip": str(target_ip),
        "best_route": public_route(best_route),
        "matching_routes": [public_route(route) for route in matching_routes[:20]],
        "routes_parsed": len(routes),
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# Route Lookup", "", f"- Destination IP: `{target_ip}`", f"- Routes parsed: `{len(routes)}`", ""]
    if not best_route:
        lines.append("No matching route found.")
        return "\n".join(lines)

    lines.extend(
        [
            "## Best Match",
            "",
            format_table(
                ["Network", "Interface", "Gateway", "Code", "Distance", "Metric"],
                [
                    [
                        best_route["network"],
                        best_route["interface"] or "-",
                        best_route["gateway"] or "-",
                        best_route["code"],
                        best_route["distance"] or "-",
                        best_route["metric"] or "-",
                    ]
                ],
            ),
            "",
        ]
    )
    if len(matching_routes) > 1:
        rows = [
            [
                route["network"],
                route["interface"] or "-",
                route["gateway"] or "-",
                route["code"],
                route["distance"] or "-",
                route["metric"] or "-",
            ]
            for route in matching_routes[:10]
        ]
        lines.extend(["## Matching Routes", "", format_table(["Network", "Interface", "Gateway", "Code", "Distance", "Metric"], rows)])
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_policy_routes",
    annotations={
        "title": "Get Fortigate Policy Routes",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_policy_routes(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return policy-based routing rules that can override normal routing-table lookup.

    Use this before concluding how a flow should route, because PBR may override longest-prefix routing.
    """

    return await execute_readonly(READONLY_COMMANDS["policy_routes"], response_format)


@mcp.tool(
    name="fortigate_get_firewall_policies",
    annotations={
        "title": "Get Fortigate Firewall Policies",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_firewall_policies(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run 'show firewall policy' on the Fortigate and return firewall policy configuration."""

    return await execute_readonly(READONLY_COMMANDS["firewall_policies"], response_format)


@mcp.tool(
    name="fortigate_get_local_in_policy",
    annotations={
        "title": "Get Fortigate Local-in Policy",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_local_in_policy(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return local-in firewall policy config for traffic destined to the Fortigate itself.

    Use this when auditing management, VPN, routing protocols, ping, or other services that terminate on the firewall.
    """

    return await execute_readonly(READONLY_COMMANDS["local_in_policy"], response_format)


@mcp.tool(
    name="fortigate_get_ipsec_vpns",
    annotations={
        "title": "Get Fortigate IPsec VPNs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_ipsec_vpns(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return IPsec tunnel status and phase1/phase2 VPN configuration."""

    commands = [
        READONLY_COMMANDS["ipsec_tunnel_summary"],
        READONLY_COMMANDS["ipsec_phase1_interface"],
        READONLY_COMMANDS["ipsec_phase1"],
        READONLY_COMMANDS["ipsec_phase2_interface"],
        READONLY_COMMANDS["ipsec_phase2"],
    ]

    results = []
    for command in commands:
        try:
            safe_command = validate_readonly_command(command)
            results.append(await run_ssh_command(safe_command))
        except Exception as exc:
            results.append(
                {
                    "command": command,
                    "exit_status": 1,
                    "stdout": "",
                    "stderr": str(exc),
                    "truncated": False,
                }
            )

    if response_format == ResponseFormat.JSON:
        return json.dumps({"results": results}, indent=2, ensure_ascii=False)

    sections = ["# Fortigate IPsec VPNs", ""]
    for result in results:
        sections.extend(
            [
                f"## `{result['command']}`",
                "",
                "```text",
                result["stdout"].strip() or result["stderr"].strip() or "(empty)",
                "```",
                "",
            ]
        )
    return "\n".join(sections)


@mcp.tool(
    name="fortigate_get_ssl_vpn_users",
    annotations={
        "title": "Get Fortigate SSL VPN Users",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_ssl_vpn_users(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run 'get vpn ssl monitor' and return currently connected SSL-VPN users."""

    return await execute_readonly(READONLY_COMMANDS["ssl_vpn_monitor"], response_format)


@mcp.tool(
    name="fortigate_run_audit_readonly",
    annotations={
        "title": "Run Fortigate Read-only Audit",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_run_audit_readonly(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run a closed set of read-only audit commands and return security findings.

    The audit checks firmware age, admin exposure, broad firewall policies, SSL-VPN
    posture, IPsec tunnel status, logging availability, and basic health signals.
    Sensitive configuration fields are redacted before analysis/output.
    """

    results: list[dict[str, Any]] = []
    for key in AUDIT_COMMAND_KEYS:
        command = READONLY_COMMANDS[key]
        try:
            safe_command = validate_readonly_command(command)
            result = await run_ssh_command(safe_command)
            result["key"] = key
            results.append(result)
        except Exception as exc:
            results.append(
                {
                    "key": key,
                    "command": command,
                    "exit_status": 1,
                    "stdout": "",
                    "stderr": str(exc),
                    "truncated": False,
                }
            )

    return format_audit_report(results, response_format)


@mcp.tool(
    name="fortigate_get_public_exposure",
    annotations={
        "title": "Get Fortigate Public Exposure",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_public_exposure(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """List VIP/public NAT exposure and firewall policies that reference VIP objects."""

    results = await collect_command_keys(["vip_objects", "firewall_policies"])
    outputs = {result["key"]: result.get("stdout", "") for result in results}
    vip_rows = parse_vip_rows(outputs.get("vip_objects", ""))
    policy_rows = parse_policy_rows(outputs.get("firewall_policies", ""))
    vip_names = {row["name"] for row in vip_rows}

    policy_refs: dict[str, list[str]] = {name: [] for name in vip_names}
    broad_vip_policies: list[str] = []
    for policy in policy_rows:
        dstaddr = set(policy["dstaddr"])
        refs = sorted(dstaddr.intersection(vip_names))
        if "all" in {value.lower() for value in dstaddr} and any(
            intf.lower().startswith("wan") for intf in policy["srcintf"]
        ):
            broad_vip_policies.append(policy["id"])
        for ref in refs:
            policy_refs[ref].append(policy["id"])

    payload = {
        "vip_count": len(vip_rows),
        "vips": [
            {
                **row,
                "referenced_by_policies": policy_refs.get(row["name"], []),
            }
            for row in vip_rows
        ],
        "wan_policies_with_dstaddr_all": broad_vip_policies,
        "commands": [{"command": result["command"], "exit_status": result["exit_status"]} for result in results],
    }

    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    table_rows = [
        [
            row["name"],
            row["extintf"] or "-",
            row["extip"] or "-",
            row["mappedip"] or "-",
            row["extport"] or "all",
            row["mappedport"] or "-",
            ", ".join(policy_refs.get(row["name"], [])) or "-",
        ]
        for row in vip_rows
    ]
    lines = ["# Public Exposure", "", f"VIP objects: {len(vip_rows)}", ""]
    if table_rows:
        lines.append(format_table(["VIP", "Ext Intf", "Ext IP", "Mapped IP", "Ext Port", "Mapped Port", "Policies"], table_rows))
    if broad_vip_policies:
        lines.extend(["", f"WAN policies with `dstaddr all`: {', '.join(broad_vip_policies)}"])
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_nat_overview",
    annotations={
        "title": "Get Fortigate NAT Overview",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_nat_overview(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return DNAT/VIP, VIP groups, IP pools, central SNAT, and firewall NAT policy references.

    Use this when troubleshooting translated traffic or auditing public/internal NAT exposure.
    """

    results = await collect_command_keys(["vip_objects", "vip_groups", "ippools", "central_snat", "firewall_policies"])
    outputs = {result["key"]: result.get("stdout", "") for result in results}
    vip_rows = parse_vip_rows(outputs.get("vip_objects", ""))
    policies = parse_policy_rows(outputs.get("firewall_policies", ""))
    nat_policies = [
        {
            "id": policy["id"],
            "name": policy["name"],
            "srcintf": policy["srcintf"],
            "dstintf": policy["dstintf"],
            "srcaddr": policy["srcaddr"],
            "dstaddr": policy["dstaddr"],
            "service": policy["service"],
            "nat": policy["nat"],
            "ippool": get_set_line(policy["raw"], "ippool") or "disable",
            "poolname": quoted_values(policy["raw"], "poolname"),
        }
        for policy in policies
        if policy["nat"] == "enable" or get_set_line(policy["raw"], "ippool") == "enable"
    ]
    payload = {
        "vips": vip_rows,
        "vip_groups_raw": outputs.get("vip_groups", ""),
        "ippools_raw": outputs.get("ippools", ""),
        "central_snat_raw": outputs.get("central_snat", ""),
        "nat_policies": nat_policies,
        "commands": [{"command": result["command"], "exit_status": result["exit_status"]} for result in results],
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# NAT Overview", "", f"- VIP objects: `{len(vip_rows)}`", f"- NAT policies: `{len(nat_policies)}`", ""]
    if vip_rows:
        rows = [
            [
                row["name"],
                row["extintf"] or "-",
                row["extip"] or "-",
                row["mappedip"] or "-",
                row["extport"] or "all",
                row["mappedport"] or "-",
            ]
            for row in vip_rows[:50]
        ]
        lines.extend(["## VIP / DNAT", "", format_table(["VIP", "Ext Intf", "Ext IP", "Mapped IP", "Ext Port", "Mapped Port"], rows), ""])
    if nat_policies:
        rows = [
            [
                item["id"],
                item["name"] or "-",
                ", ".join(item["srcintf"]),
                ", ".join(item["dstintf"]),
                item["nat"],
                item["ippool"],
                ", ".join(item["poolname"]) or "-",
            ]
            for item in nat_policies[:50]
        ]
        lines.extend(["## SNAT Policies", "", format_table(["ID", "Name", "Src Intf", "Dst Intf", "NAT", "IP Pool", "Pool Name"], rows), ""])
    for title, key in [("IP Pools", "ippools"), ("Central SNAT", "central_snat"), ("VIP Groups", "vip_groups")]:
        raw = outputs.get(key, "").strip()
        if raw:
            lines.extend([f"## {title}", "", "```text", raw[:6000], "```", ""])
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_proxy_policy_overview",
    annotations={
        "title": "Get Fortigate Proxy Policy Overview",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_proxy_policy_overview(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return explicit-proxy and access-proxy policy configuration that can affect proxied traffic."""

    results = await collect_command_keys(["proxy_policy", "access_proxy"])
    if response_format == ResponseFormat.JSON:
        return json.dumps({"results": results}, indent=2, ensure_ascii=False)
    lines = ["# Proxy Policy Overview", ""]
    for result in results:
        lines.extend(["## `" + result["command"] + "`", "", "```text", result.get("stdout", "").strip() or result.get("stderr", "").strip() or "(empty)", "```", ""])
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_find_policy_by_ip",
    annotations={
        "title": "Find Fortigate Policies by IP",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_find_policy_by_ip(
    ip: IpAddressParam,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Find firewall policies that reference address objects containing an IPv4 address."""

    try:
        target_ip = ipaddress.ip_address(ip)
    except ValueError as exc:
        return format_error(ValueError(f"Invalid IP address '{ip}': {exc}"))

    results = await collect_command_keys(["address_objects", "firewall_policies"])
    outputs = {result["key"]: result.get("stdout", "") for result in results}
    address_objects = parse_firewall_addresses(outputs.get("address_objects", ""))
    matches = {
        name: obj
        for name, obj in address_objects.items()
        if object_matches_ip(obj, target_ip)
    }
    match_names = set(matches.keys())
    policy_rows = parse_policy_rows(outputs.get("firewall_policies", ""))
    policy_matches = []

    for policy in policy_rows:
        src_matches = sorted(match_names.intersection(policy["srcaddr"]))
        dst_matches = sorted(match_names.intersection(policy["dstaddr"]))
        if src_matches or dst_matches or "all" in {value.lower() for value in policy["srcaddr"] + policy["dstaddr"]}:
            policy_matches.append(
                {
                    "id": policy["id"],
                    "name": policy["name"],
                    "status": policy["status"],
                    "srcintf": policy["srcintf"],
                    "dstintf": policy["dstintf"],
                    "srcaddr_matches": src_matches,
                    "dstaddr_matches": dst_matches,
                    "srcaddr": policy["srcaddr"],
                    "dstaddr": policy["dstaddr"],
                    "service": policy["service"],
                    "action": policy["action"],
                    "nat": policy["nat"],
                }
            )

    payload = {
        "ip": str(target_ip),
        "matching_address_objects": matches,
        "policies": policy_matches,
        "note": "Policies containing 'all' are included because they may apply to this IP depending on interfaces/routing.",
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# Policy Search by IP", "", f"IP: `{target_ip}`", ""]
    lines.append(f"Matching address objects: {', '.join(matches.keys()) if matches else 'none'}")
    lines.append("")
    if policy_matches:
        rows = [
            [
                item["id"],
                item["name"] or "-",
                item["status"],
                ", ".join(item["srcintf"]),
                ", ".join(item["dstintf"]),
                ", ".join(item["srcaddr_matches"] or item["srcaddr"]),
                ", ".join(item["dstaddr_matches"] or item["dstaddr"]),
                ", ".join(item["service"]),
            ]
            for item in policy_matches
        ]
        lines.append(format_table(["ID", "Name", "Status", "Src Intf", "Dst Intf", "Src Addr", "Dst Addr", "Service"], rows))
    else:
        lines.append("No matching policies found.")
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_find_policy_for_flow",
    annotations={
        "title": "Find Fortigate Policy For Flow",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_find_policy_for_flow(
    src_ip: IpAddressParam,
    dst_ip: IpAddressParam,
    protocol: RequiredProtocolParam,
    dst_port: PortParam = None,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Find candidate firewall policies for a source/destination/protocol flow.

    Use this for read-only policy troubleshooting when debug flow is not appropriate.
    The result is a static approximation based on address objects, service objects, policy order, and route lookup.
    """

    source_ip = parse_ipv4(src_ip, "Source IP")
    destination_ip = parse_ipv4(dst_ip, "Destination IP")
    results = await collect_command_keys(
        ["firewall_policies", "address_objects", "address_groups", "service_objects", "service_groups", "routing_table"]
    )
    outputs = {result["key"]: result.get("stdout", "") for result in results}
    flow_context = candidate_policies_for_flow(
        outputs.get("firewall_policies", ""),
        outputs.get("address_objects", ""),
        outputs.get("address_groups", ""),
        outputs.get("service_objects", ""),
        outputs.get("service_groups", ""),
        outputs.get("routing_table", ""),
        source_ip,
        destination_ip,
        protocol,
        dst_port,
    )
    source_route = flow_context["source_route"]
    best_route = flow_context["destination_route"]
    candidates = flow_context["candidate_policies"]
    source_interface = source_route["interface"] if source_route else ""

    payload = {
        "flow": {"src_ip": str(source_ip), "dst_ip": str(destination_ip), "protocol": protocol, "dst_port": dst_port},
        "best_route_to_source": source_route,
        "best_route_to_destination": best_route,
        "candidate_policies": candidates,
        "note": "Static policy matching approximation using route-derived interfaces. Policy routes, central NAT, identity, schedules, local-in traffic, and dynamic objects can affect real forwarding.",
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = [
        "# Policy Lookup For Flow",
        "",
        f"- Flow: `{source_ip} -> {destination_ip}` protocol `{protocol}` dst_port `{dst_port or '-'}`",
        f"- Estimated source interface: `{source_interface or '-'}`",
        f"- Best route interface: `{best_route['interface'] if best_route else '-'}`",
        f"- Candidate policies: `{len(candidates)}`",
        "",
    ]
    if not candidates:
        lines.append("No candidate policies found from static object matching.")
        return "\n".join(lines)

    rows = [
        [
            item["id"],
            item["name"] or "-",
            item["status"],
            item["action"] or "-",
            ", ".join(item["srcintf"]),
            ", ".join(item["dstintf"]),
            ", ".join(item["matched_srcaddr"]),
            ", ".join(item["matched_dstaddr"]),
            ", ".join(item["matched_service"]),
            item["nat"],
            item["logtraffic"] or "-",
        ]
        for item in candidates[:30]
    ]
    lines.append(
        format_table(
            ["ID", "Name", "Status", "Action", "Src Intf", "Dst Intf", "Src Match", "Dst Match", "Service", "NAT", "Log"],
            rows,
        )
    )
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_explain_flow",
    annotations={
        "title": "Explain Fortigate Flow",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_explain_flow(
    src_ip: IpAddressParam,
    dst_ip: IpAddressParam,
    protocol: RequiredProtocolParam,
    dst_port: PortParam = None,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Explain a Fortigate flow by combining routes, PBR, policies, NAT, sessions, traffic logs, and SD-WAN context.

    Use this as the first tool for end-to-end traffic troubleshooting from an agent.
    It is read-only and bounded: logs are limited, session filters are specific, and no debug flow is enabled.
    """

    source_ip = parse_ipv4(src_ip, "Source IP")
    destination_ip = parse_ipv4(dst_ip, "Destination IP")
    results = await collect_command_keys(
        [
            "firewall_policies",
            "address_objects",
            "address_groups",
            "service_objects",
            "service_groups",
            "routing_table",
            "policy_routes",
            "vip_objects",
            "vip_groups",
            "ippools",
            "central_snat",
            "sdwan_health_check",
            "sdwan_service",
        ]
    )
    outputs = {result["key"]: result.get("stdout", "") for result in results}
    flow_context = candidate_policies_for_flow(
        outputs.get("firewall_policies", ""),
        outputs.get("address_objects", ""),
        outputs.get("address_groups", ""),
        outputs.get("service_objects", ""),
        outputs.get("service_groups", ""),
        outputs.get("routing_table", ""),
        source_ip,
        destination_ip,
        protocol,
        dst_port,
    )

    vip_matches = []
    for vip in parse_vip_rows(outputs.get("vip_objects", "")):
        mapped_ips = [item for item in vip["mappedip"].split() if item]
        if str(destination_ip) in mapped_ips or vip["extip"] == str(destination_ip):
            vip_matches.append(vip)

    session_commands = [
        "diagnose sys session filter clear",
        f"diagnose sys session filter src {source_ip}",
        f"diagnose sys session filter dst {destination_ip}",
    ]
    if dst_port:
        session_commands.append(f"diagnose sys session filter dport {dst_port}")
    session_commands.extend([f"diagnose sys session filter proto {protocol}", "diagnose sys session list", "diagnose sys session filter clear"])
    try:
        session_results = await run_ssh_command_sequence(session_commands)
        session_output = session_results[-2].get("stdout", "") if len(session_results) >= 2 else ""
        session_summary = summarize_session_trace(session_output)
    except Exception as exc:
        session_summary = {"error": str(exc), "session_count": 0, "policy_ids": [], "states": [], "hooks": [], "evidence_lines": []}

    log_commands = [
        "execute log filter category traffic",
        f"execute log filter field srcip {source_ip}",
        "execute log filter view-lines 25",
        "execute log display",
    ]
    try:
        log_results = await run_ssh_command_sequence(log_commands)
        log_events = [
            event
            for event in parse_fortigate_log_lines(log_results[-1].get("stdout", "") if log_results else "")
            if event.get("dstip") == str(destination_ip) and (not dst_port or event.get("dstport") == str(dst_port))
        ][:10]
        log_errors = detect_log_access_error(log_results)
    except Exception as exc:
        log_events = []
        log_errors = [str(exc)]

    payload = {
        "flow": {"src_ip": str(source_ip), "dst_ip": str(destination_ip), "protocol": protocol, "dst_port": dst_port},
        **flow_context,
        "policy_routes_raw": outputs.get("policy_routes", ""),
        "vip_matches": vip_matches,
        "ippools_raw": outputs.get("ippools", ""),
        "central_snat_raw": outputs.get("central_snat", ""),
        "session_summary": session_summary,
        "traffic_log_events": log_events,
        "traffic_log_errors": log_errors,
        "sdwan_health_check_raw": outputs.get("sdwan_health_check", ""),
        "sdwan_service_raw": outputs.get("sdwan_service", ""),
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    destination_route = flow_context["destination_route"]
    candidates = flow_context["candidate_policies"]
    lines = [
        "# Flow Explanation",
        "",
        f"- Flow: `{source_ip} -> {destination_ip}` protocol `{protocol}` dst_port `{dst_port or '-'}`",
        f"- Destination route: `{destination_route['network'] if destination_route else '-'}` via `{destination_route['interface'] if destination_route else '-'}`",
        f"- Candidate policies: `{len(candidates)}`",
        f"- Active sessions: `{session_summary.get('session_count', 0)}`",
        f"- Traffic log matches: `{len(log_events)}`",
        "",
    ]
    if candidates:
        rows = [
            [
                item["id"],
                item["name"] or "-",
                item["status"],
                item["action"] or "-",
                ", ".join(item["srcintf"]),
                ", ".join(item["dstintf"]),
                ", ".join(item["matched_srcaddr"]),
                ", ".join(item["matched_dstaddr"]),
                ", ".join(item["matched_service"]),
                item["nat"],
                ", ".join(item["poolname"]) or "-",
            ]
            for item in candidates[:15]
        ]
        lines.extend(["## Candidate Policies", "", format_table(["ID", "Name", "Status", "Action", "Src Intf", "Dst Intf", "Src Match", "Dst Match", "Service", "NAT", "Pool"], rows), ""])
    if vip_matches:
        rows = [[item["name"], item["extintf"], item["extip"] or "-", item["mappedip"], item["extport"] or "all", item["mappedport"] or "-"] for item in vip_matches]
        lines.extend(["## VIP / DNAT Matches", "", format_table(["VIP", "Ext Intf", "Ext IP", "Mapped IP", "Ext Port", "Mapped Port"], rows), ""])
    if session_summary.get("evidence_lines"):
        lines.extend(["## Active Session Evidence", "", "```text", "\n".join(session_summary["evidence_lines"][:30]), "```", ""])
    if log_events:
        rows = [
            [
                event.get("date", ""),
                event.get("time", ""),
                event.get("policyid", ""),
                event.get("action", ""),
                event.get("srcip", ""),
                event.get("dstip", ""),
                event.get("dstport", ""),
                event.get("trandisp", ""),
                event.get("sentbyte", ""),
                event.get("rcvdbyte", ""),
            ]
            for event in log_events
        ]
        lines.extend(["## Recent Traffic Logs", "", format_table(["Date", "Time", "Policy", "Action", "Src", "Dst", "DPort", "NAT", "Sent", "Received"], rows), ""])
    if outputs.get("policy_routes", "").strip() and "config router policy\nend" not in outputs.get("policy_routes", "").strip():
        lines.extend(["## Policy Routes", "", "```text", outputs["policy_routes"].strip()[:3000], "```", ""])
    if "Health Check" in outputs.get("sdwan_health_check", ""):
        lines.extend(["## SD-WAN Health Snapshot", "", "```text", "\n".join(outputs["sdwan_health_check"].splitlines()[:12]), "```"])
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_policy_risk_summary",
    annotations={
        "title": "Get Fortigate Policy Risk Summary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_policy_risk_summary(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Summarize firewall policy risks such as broad objects, service ALL, disabled logging, and disabled rules."""

    result = await run_ssh_command(validate_readonly_command(READONLY_COMMANDS["firewall_policies"]))
    policies = parse_policy_rows(result.get("stdout", ""))
    findings = []
    for policy in policies:
        issues = []
        src_lower = {item.lower() for item in policy["srcaddr"]}
        dst_lower = {item.lower() for item in policy["dstaddr"]}
        service_lower = {item.lower() for item in policy["service"]}
        if "all" in src_lower:
            issues.append("srcaddr all")
        if "all" in dst_lower:
            issues.append("dstaddr all")
        if "all" in service_lower:
            issues.append("service ALL")
        if policy["status"] == "disable":
            issues.append("disabled")
        if policy["action"] == "accept" and not policy["logtraffic"]:
            issues.append("logtraffic unset")
        if policy["action"] == "accept" and policy["logtraffic"] == "disable":
            issues.append("logtraffic disable")
        if not policy["name"]:
            issues.append("no name")
        if issues:
            findings.append({**policy, "issues": issues})

    payload = {"policy_count": len(policies), "risky_policy_count": len(findings), "policies": findings}
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# Policy Risk Summary", "", f"- Policies parsed: `{len(policies)}`", f"- Policies with findings: `{len(findings)}`", ""]
    if not findings:
        lines.append("No policy risk patterns found by the automatic checks.")
        return "\n".join(lines)
    rows = [
        [
            item["id"],
            item["name"] or "-",
            item["status"],
            ", ".join(item["srcintf"]),
            ", ".join(item["dstintf"]),
            ", ".join(item["srcaddr"]),
            ", ".join(item["dstaddr"]),
            ", ".join(item["service"]),
            item["logtraffic"] or "-",
            "; ".join(item["issues"]),
        ]
        for item in findings[:60]
    ]
    lines.append(format_table(["ID", "Name", "Status", "Src Intf", "Dst Intf", "Src Addr", "Dst Addr", "Service", "Log", "Issues"], rows))
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_security_profiles_overview",
    annotations={
        "title": "Get Fortigate Security Profiles Overview",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_security_profiles_overview(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Show security profiles referenced by firewall policies plus UTM profile definitions.

    Use this when traffic is allowed by policy but may be blocked or inspected by AV, IPS, webfilter, app control, or SSL inspection.
    """

    results = await collect_command_keys(["firewall_policies", "utm_av", "utm_webfilter", "utm_ips", "utm_appctrl", "utm_ssl_ssh"])
    outputs = {result["key"]: result.get("stdout", "") for result in results}
    profile_fields = ["av-profile", "webfilter-profile", "ips-sensor", "application-list", "ssl-ssh-profile"]
    policy_refs = []
    for policy in parse_policy_rows(outputs.get("firewall_policies", "")):
        refs = {field: " ".join(quoted_values(policy["raw"], field)) for field in profile_fields}
        refs = {field: value for field, value in refs.items() if value}
        if refs:
            policy_refs.append({"id": policy["id"], "name": policy["name"], **refs})

    payload = {
        "policy_profile_references": policy_refs,
        "profile_outputs": {key: outputs.get(key, "") for key in ["utm_av", "utm_webfilter", "utm_ips", "utm_appctrl", "utm_ssl_ssh"]},
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# Security Profiles Overview", "", f"- Policies with security profiles: `{len(policy_refs)}`", ""]
    if policy_refs:
        rows = [
            [
                item["id"],
                item["name"] or "-",
                item.get("av-profile", "-"),
                item.get("webfilter-profile", "-"),
                item.get("ips-sensor", "-"),
                item.get("application-list", "-"),
                item.get("ssl-ssh-profile", "-"),
            ]
            for item in policy_refs[:80]
        ]
        lines.append(format_table(["ID", "Name", "AV", "Webfilter", "IPS", "AppCtrl", "SSL/SSH"], rows))
    else:
        lines.append("No policy security profile references parsed.")
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_traffic_controls",
    annotations={
        "title": "Get Fortigate Traffic Controls",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_traffic_controls(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return DoS policies, traffic shapers, and per-IP shapers that can drop or rate-limit traffic."""

    results = await collect_command_keys(["dos_policy", "traffic_shaper", "per_ip_shaper"])
    if response_format == ResponseFormat.JSON:
        return json.dumps({"results": results}, indent=2, ensure_ascii=False)

    lines = ["# Traffic Controls", ""]
    for result in results:
        lines.extend(
            [
                f"## `{result['command']}`",
                "",
                "```text",
                result.get("stdout", "").strip() or result.get("stderr", "").strip() or "(empty)",
                "```",
                "",
            ]
        )
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_admin_access_surface",
    annotations={
        "title": "Get Fortigate Admin Access Surface",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_admin_access_surface(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Audit Fortigate administrative exposure from interfaces, admin accounts, and local-in policy.

    Use this to find SSH/HTTPS/HTTP/Telnet management access, admins without trusted hosts, and local-in rules.
    """

    results = await collect_command_keys(["system_interfaces_config", "system_admin", "local_in_policy"])
    outputs = {result["key"]: result.get("stdout", "") for result in results}
    interfaces = []
    for name, block in parse_config_blocks(outputs.get("system_interfaces_config", "")).items():
        allowaccess = quoted_values(block, "allowaccess")
        if allowaccess:
            interfaces.append(
                {
                    "name": name,
                    "ip": get_set_line(block, "ip") or "",
                    "type": get_set_line(block, "type") or "",
                    "alias": (get_set_line(block, "alias") or "").strip('"'),
                    "allowaccess": allowaccess,
                    "risky": sorted(set(allowaccess).intersection({"http", "telnet"})),
                    "wan_like": name.lower().startswith("wan"),
                }
            )

    admins = []
    for name, block in parse_config_blocks(outputs.get("system_admin", "")).items():
        trusthosts = re.findall(r"(?m)^\s*set\s+trusthost\d+\s+(.+)$", block)
        admins.append(
            {
                "name": name,
                "accprofile": " ".join(quoted_values(block, "accprofile")) or get_set_line(block, "accprofile") or "",
                "trusthosts": trusthosts,
                "two_factor": get_set_line(block, "two-factor") or "",
                "without_trusthost": not trusthosts,
            }
        )

    local_in = parse_local_in_policy_rows(outputs.get("local_in_policy", ""))
    payload = {"interfaces": interfaces, "admins": admins, "local_in_policy": local_in}
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# Admin Access Surface", ""]
    lines.extend(["## Interface Management Access", ""])
    if interfaces:
        rows = [
            [
                item["name"],
                item["ip"] or "-",
                ", ".join(item["allowaccess"]),
                "yes" if item["wan_like"] else "no",
                ", ".join(item["risky"]) or "-",
            ]
            for item in interfaces
        ]
        lines.append(format_table(["Interface", "IP", "Allowaccess", "WAN-like", "Risky"], rows))
    else:
        lines.append("No interface allowaccess entries found.")

    lines.extend(["", "## Admin Accounts", ""])
    rows = [
        [
            item["name"],
            item["accprofile"] or "-",
            "yes" if item["without_trusthost"] else "no",
            item["two_factor"] or "-",
            "; ".join(item["trusthosts"]) or "-",
        ]
        for item in admins
    ]
    lines.append(format_table(["Admin", "Profile", "No Trusthost", "2FA", "Trusthosts"], rows) if rows else "No admin blocks parsed.")

    lines.extend(["", "## Local-in Policy", ""])
    if local_in:
        rows = [
            [
                item["id"],
                item["status"],
                ", ".join(item["intf"]) or "-",
                ", ".join(item["srcaddr"]) or "-",
                ", ".join(item["service"]) or "-",
                item["action"] or "-",
            ]
            for item in local_in
        ]
        lines.append(format_table(["ID", "Status", "Interface", "Source", "Service", "Action"], rows))
    else:
        lines.append("No local-in policy entries parsed, or local-in policy is not configured.")
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_external_attack_surface",
    annotations={
        "title": "Get Fortigate External Attack Surface",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_external_attack_surface(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Summarize externally reachable Fortigate services and published internal services.

    Use this for perimeter audits. It aggregates WAN-like interface management, VIP/DNAT, ZTNA/access-proxy,
    SSL-VPN settings, IPsec peers, and local-in policy without changing the firewall.
    """

    results = await collect_command_keys(
        [
            "system_interfaces_config",
            "system_admin",
            "local_in_policy",
            "vip_objects",
            "vip_groups",
            "firewall_policies",
            "proxy_policy",
            "access_proxy",
            "ssl_vpn_settings",
            "ipsec_phase1_interface",
            "ipsec_phase1",
            "ipsec_tunnel_summary",
        ]
    )
    outputs = {result["key"]: result.get("stdout", "") for result in results}

    wan_interfaces = []
    for name, block in parse_config_blocks(outputs.get("system_interfaces_config", "")).items():
        allowaccess = quoted_values(block, "allowaccess")
        role = get_set_line(block, "role") or ""
        if name.lower().startswith("wan") or role.strip('"') == "wan":
            wan_interfaces.append(
                {
                    "name": name,
                    "ip": get_set_line(block, "ip") or "",
                    "role": role.strip('"'),
                    "allowaccess": allowaccess,
                    "admin_services": sorted(set(allowaccess).intersection({"http", "https", "ssh", "telnet", "fgfm"})),
                }
            )

    vip_rows = parse_vip_rows(outputs.get("vip_objects", ""))
    policies = parse_policy_rows(outputs.get("firewall_policies", ""))
    vip_names = {vip["name"] for vip in vip_rows}
    vip_policy_refs: dict[str, list[str]] = {name: [] for name in vip_names}
    for policy in policies:
        for ref in sorted(set(policy["dstaddr"]).intersection(vip_names)):
            vip_policy_refs[ref].append(policy["id"])

    exposed_vips = [
        {**vip, "policies": vip_policy_refs.get(vip["name"], [])}
        for vip in vip_rows
        if vip_policy_refs.get(vip["name"]) or vip["extintf"].lower().startswith("wan")
    ]

    ipsec_peers = []
    for name, block in {
        **parse_config_blocks(outputs.get("ipsec_phase1_interface", "")),
        **parse_config_blocks(outputs.get("ipsec_phase1", "")),
    }.items():
        ipsec_peers.append(
            {
                "name": name,
                "interface": " ".join(quoted_values(block, "interface")),
                "remote_gw": (get_set_line(block, "remote-gw") or "").strip('"'),
                "peertype": get_set_line(block, "peertype") or "",
                "net_device": get_set_line(block, "net-device") or "",
            }
        )

    ssl_settings = outputs.get("ssl_vpn_settings", "")
    ssl_summary = {
        "servercert": " ".join(quoted_values(ssl_settings, "servercert")),
        "port": get_set_line(ssl_settings, "port") or "",
        "source_interface": quoted_values(ssl_settings, "source-interface"),
        "source_address": quoted_values(ssl_settings, "source-address"),
        "tunnel_ip_pools": quoted_values(ssl_settings, "tunnel-ip-pools"),
    }
    local_in = parse_local_in_policy_rows(outputs.get("local_in_policy", ""))
    payload = {
        "wan_interfaces": wan_interfaces,
        "published_vips": exposed_vips,
        "proxy_policy_raw": outputs.get("proxy_policy", ""),
        "access_proxy_raw": outputs.get("access_proxy", ""),
        "ssl_vpn": ssl_summary,
        "ipsec_peers": ipsec_peers,
        "ipsec_tunnel_summary_raw": outputs.get("ipsec_tunnel_summary", ""),
        "local_in_policy": local_in,
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# External Attack Surface", ""]
    lines.extend(["## WAN-like Interfaces", ""])
    if wan_interfaces:
        rows = [
            [
                item["name"],
                item["ip"] or "-",
                ", ".join(item["allowaccess"]) or "-",
                ", ".join(item["admin_services"]) or "-",
            ]
            for item in wan_interfaces
        ]
        lines.append(format_table(["Interface", "IP", "Allowaccess", "Admin Services"], rows))
    else:
        lines.append("No WAN-like interfaces parsed.")

    lines.extend(["", "## Published VIPs / DNAT", ""])
    if exposed_vips:
        rows = [
            [
                item["name"],
                item["extintf"] or "-",
                item["extip"] or "-",
                item["mappedip"] or "-",
                item["extport"] or "all",
                item["mappedport"] or "-",
                ", ".join(item["policies"]) or "-",
            ]
            for item in exposed_vips[:80]
        ]
        lines.append(format_table(["VIP", "Ext Intf", "Ext IP", "Mapped IP", "Ext Port", "Mapped Port", "Policies"], rows))
    else:
        lines.append("No published VIPs found.")

    lines.extend(["", "## SSL-VPN", ""])
    lines.append(
        format_table(
            ["Port", "Source Interface", "Source Address", "Tunnel Pools", "Certificate"],
            [
                [
                    ssl_summary["port"] or "-",
                    ", ".join(ssl_summary["source_interface"]) or "-",
                    ", ".join(ssl_summary["source_address"]) or "-",
                    ", ".join(ssl_summary["tunnel_ip_pools"]) or "-",
                    ssl_summary["servercert"] or "-",
                ]
            ],
        )
    )

    lines.extend(["", "## IPsec Peers", ""])
    if ipsec_peers:
        rows = [[item["name"], item["interface"] or "-", item["remote_gw"] or "-", item["peertype"] or "-"] for item in ipsec_peers[:60]]
        lines.append(format_table(["Phase1", "Interface", "Remote GW", "Peer Type"], rows))
    else:
        lines.append("No IPsec phase1 peers parsed.")

    if outputs.get("proxy_policy", "").strip() and "config firewall proxy-policy\nend" not in outputs.get("proxy_policy", "").strip():
        lines.extend(["", "## Proxy / ZTNA", "", "```text", outputs["proxy_policy"].strip()[:4000], "```"])

    lines.extend(["", "## Local-in Policy", ""])
    if local_in:
        rows = [[item["id"], item["status"], ", ".join(item["intf"]) or "-", ", ".join(item["srcaddr"]) or "-", ", ".join(item["service"]) or "-", item["action"] or "-"] for item in local_in]
        lines.append(format_table(["ID", "Status", "Interface", "Source", "Service", "Action"], rows))
    else:
        lines.append("No local-in policy entries configured.")
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_interface_health",
    annotations={
        "title": "Get Fortigate Interface Health",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_interface_health(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return link/speed/duplex/drop health for physical Fortigate interfaces."""

    list_result = await run_ssh_command(validate_readonly_command(READONLY_COMMANDS["hardware_nic"]))
    ports = [
        line.strip()
        for line in list_result.get("stdout", "").splitlines()
        if line.startswith("\t") and line.strip()
    ]

    details = []
    for port in ports[:40]:
        result = await run_ssh_command(validate_readonly_command(f"get hardware nic {port}"))
        fields = parse_hardware_nic(result.get("stdout", ""))
        details.append({"name": port, **fields})

    payload = {"interfaces": details}
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    rows = [
        [
            item["name"],
            item.get("Admin", "-"),
            item.get("netdev status", "-"),
            item.get("link_status", "-"),
            item.get("Speed", "-"),
            item.get("Duplex", "-"),
            item.get("Host Tx dropped", "0"),
        ]
        for item in details
    ]
    return "# Interface Health\n\n" + format_table(
        ["Interface", "Admin", "Netdev", "Link", "Speed", "Duplex", "Host Tx Dropped"],
        rows,
    )


@mcp.tool(
    name="fortigate_get_vpn_overview",
    annotations={
        "title": "Get Fortigate VPN Overview",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_vpn_overview(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return SSL-VPN users and IPsec tunnel status in one concise view."""

    results = await collect_command_keys(["ssl_vpn_monitor", "ipsec_tunnel_summary"])
    outputs = {result["key"]: result.get("stdout", "") for result in results}
    ssl_users = []
    for line in outputs.get("ssl_vpn_monitor", "").splitlines():
        if re.match(r"\s*\d+\s+", line):
            parts = [part.strip() for part in line.split("\t")]
            if len(parts) >= 7 and parts[1] != "User":
                ssl_users.append(parts)

    ipsec_rows = []
    for line in outputs.get("ipsec_tunnel_summary", "").splitlines():
        match = re.search(
            r"'([^']+)'\s+(\S+)\s+selectors\(total,up\):\s+(\d+)/(\d+)\s+rx\(pkt,err\):\s+(\d+)/(\d+)\s+tx\(pkt,err\):\s+(\d+)/(\d+)",
            line,
        )
        if match:
            name, peer, total, up, rx, rx_err, tx, tx_err = match.groups()
            ipsec_rows.append(
                {
                    "name": name,
                    "peer": peer,
                    "selectors": f"{up}/{total}",
                    "rx_packets": rx,
                    "rx_errors": rx_err,
                    "tx_packets": tx,
                    "tx_errors": tx_err,
                    "status": "up" if up == total else "down",
                }
            )

    payload = {"ssl_vpn_raw_users": ssl_users, "ipsec_tunnels": ipsec_rows}
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# VPN Overview", "", "## IPsec", ""]
    lines.append(
        format_table(
            ["Tunnel", "Peer", "Selectors", "Status", "Rx Err", "Tx Err"],
            [[row["name"], row["peer"], row["selectors"], row["status"], row["rx_errors"], row["tx_errors"]] for row in ipsec_rows],
        )
    )
    lines.extend(["", "## SSL-VPN", ""])
    if ssl_users:
        lines.append("```text")
        lines.append(outputs.get("ssl_vpn_monitor", "").strip())
        lines.append("```")
    else:
        lines.append("No SSL-VPN users found in monitor output.")
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_vpn_error_summary",
    annotations={
        "title": "Get Fortigate VPN Error Summary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_vpn_error_summary(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Summarize IPsec/SSL-VPN tunnel state and recent VPN-related error logs."""

    results = await collect_command_keys(["ipsec_tunnel_summary", "ssl_vpn_monitor"])
    commands = [
        "execute log filter category event",
        "execute log filter field subtype vpn",
        "execute log filter view-lines 300",
        "execute log display",
    ]
    try:
        log_results = await run_ssh_command_sequence(commands)
    except Exception as exc:
        log_results = [{"command": "execute log display", "exit_status": 1, "stdout": "", "stderr": str(exc), "truncated": False}]

    outputs = {result["key"]: result.get("stdout", "") for result in results}
    tunnel_rows = []
    for line in outputs.get("ipsec_tunnel_summary", "").splitlines():
        match = re.search(
            r"'([^']+)'\s+(\S+)\s+selectors\(total,up\):\s+(\d+)/(\d+)\s+rx\(pkt,err\):\s+(\d+)/(\d+)\s+tx\(pkt,err\):\s+(\d+)/(\d+)",
            line,
        )
        if match:
            name, peer, total, up, rx, rx_err, tx, tx_err = match.groups()
            tunnel_rows.append(
                {
                    "name": name,
                    "peer": peer,
                    "selectors_total": int(total),
                    "selectors_up": int(up),
                    "rx_packets": int(rx),
                    "rx_errors": int(rx_err),
                    "tx_packets": int(tx),
                    "tx_errors": int(tx_err),
                    "status": "up" if total == up else "down",
                }
            )

    events = parse_fortigate_log_lines(log_results[-1].get("stdout", "") if log_results else "")
    error_events = [event for event in events if event_is_error_like(event)]
    payload = {
        "ipsec_tunnels": tunnel_rows,
        "vpn_events_scanned": len(events),
        "vpn_error_events": error_events[:50],
        "vpn_errors_by_peer": summarize_events_by_field(error_events, "remip"),
        "log_access_errors": detect_log_access_error(log_results),
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# VPN Error Summary", "", f"- VPN events scanned: `{len(events)}`", f"- Error-like VPN events: `{len(error_events)}`", ""]
    if tunnel_rows:
        rows = [
            [
                item["name"],
                item["peer"],
                f"{item['selectors_up']}/{item['selectors_total']}",
                item["status"],
                item["rx_errors"],
                item["tx_errors"],
            ]
            for item in tunnel_rows
        ]
        lines.extend(["## IPsec Tunnels", "", format_table(["Tunnel", "Peer", "Selectors", "Status", "Rx Err", "Tx Err"], rows), ""])
    if error_events:
        rows = [
            [
                event.get("date", ""),
                event.get("time", ""),
                event.get("remip", "") or event.get("srcip", ""),
                event.get("status", ""),
                event.get("action", ""),
                event.get("msg", "") or event.get("logdesc", ""),
            ]
            for event in error_events[:25]
        ]
        lines.extend(["## Recent VPN Error Events", "", format_table(["Date", "Time", "Peer/Src", "Status", "Action", "Message"], rows)])
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_sdwan_status",
    annotations={
        "title": "Get Fortigate SD-WAN Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_sdwan_status(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return SD-WAN runtime status and configuration if SD-WAN is available on the Fortigate."""

    results = await collect_command_keys(["sdwan_health_check", "sdwan_service", "sdwan_config"])
    if response_format == ResponseFormat.JSON:
        return json.dumps({"results": results}, indent=2, ensure_ascii=False)

    lines = ["# SD-WAN Status", ""]
    for result in results:
        status = "ok" if result["exit_status"] == 0 and not detect_log_access_error([result]) else "check output"
        lines.extend(
            [
                f"## `{result['command']}`",
                "",
                f"- Status: `{status}`",
                "",
                "```text",
                result.get("stdout", "").strip() or result.get("stderr", "").strip() or "(empty)",
                "```",
                "",
            ]
        )
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_dynamic_routing_status",
    annotations={
        "title": "Get Fortigate Dynamic Routing Status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_dynamic_routing_status(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Return BGP/OSPF runtime status and routing database views where available."""

    results = await collect_command_keys(["bgp_summary", "ospf_neighbor", "routing_database"])
    if response_format == ResponseFormat.JSON:
        return json.dumps({"results": results}, indent=2, ensure_ascii=False)
    lines = ["# Dynamic Routing Status", ""]
    for result in results:
        lines.extend(
            [
                f"## `{result['command']}`",
                "",
                "```text",
                result.get("stdout", "").strip() or result.get("stderr", "").strip() or "(empty)",
                "```",
                "",
            ]
        )
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_export_readonly_snapshot",
    annotations={
        "title": "Export Fortigate Read-only Snapshot",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def fortigate_export_readonly_snapshot(
    label: SnapshotLabelParam = None,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Save a redacted local JSON snapshot of key read-only Fortigate state."""

    keys = [
        "system_status",
        "system_performance",
        "interfaces",
        "system_interfaces_config",
        "routing_table",
        "firewall_policies",
        "vip_objects",
        "ssl_vpn_settings",
        "ssl_vpn_monitor",
        "ipsec_tunnel_summary",
        "ipsec_phase1_interface",
        "ipsec_phase2_interface",
    ]
    results = await collect_command_keys(keys)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{timestamp}-{safe_snapshot_label(label)}.json"
    SNAPSHOT_DIR.mkdir(exist_ok=True)
    snapshot_path = SNAPSHOT_DIR / filename
    payload = {
        "created_at": timestamp,
        "label": safe_snapshot_label(label),
        "commands": results,
    }
    with snapshot_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)

    response = {
        "snapshot_path": str(snapshot_path),
        "command_count": len(results),
        "errors": [result for result in results if result["exit_status"] != 0],
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(response, indent=2, ensure_ascii=False)
    return (
        "# Snapshot Exported\n\n"
        f"- Path: `{snapshot_path}`\n"
        f"- Commands: `{len(results)}`\n"
        f"- Errors: `{len(response['errors'])}`"
    )


@mcp.tool(
    name="fortigate_compare_snapshots",
    annotations={
        "title": "Compare Fortigate Snapshots",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def fortigate_compare_snapshots(
    snapshot_a: SnapshotFileParam,
    snapshot_b: SnapshotFileParam,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Compare two local read-only snapshot JSON files exported by this MCP.

    Use this for audits that need to identify configuration or state changes between two collection times.
    The comparison is local-only and reports changed command sections plus added/removed line samples.
    """

    try:
        outputs_a = load_snapshot_outputs(snapshot_a)
        outputs_b = load_snapshot_outputs(snapshot_b)
    except Exception as exc:
        return format_error(exc)

    keys = sorted(set(outputs_a) | set(outputs_b))
    changes = []
    for key in keys:
        before = outputs_a.get(key, "")
        after = outputs_b.get(key, "")
        if before == after:
            continue
        before_lines = set(before.splitlines())
        after_lines = set(after.splitlines())
        added = sorted(after_lines - before_lines)
        removed = sorted(before_lines - after_lines)
        changes.append(
            {
                "key": key,
                "before_line_count": len(before.splitlines()),
                "after_line_count": len(after.splitlines()),
                "added_line_count": len(added),
                "removed_line_count": len(removed),
                "added_sample": added[:20],
                "removed_sample": removed[:20],
            }
        )

    payload = {
        "snapshot_a": snapshot_a,
        "snapshot_b": snapshot_b,
        "changed_sections": changes,
        "changed_section_count": len(changes),
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = [
        "# Snapshot Comparison",
        "",
        f"- Snapshot A: `{snapshot_a}`",
        f"- Snapshot B: `{snapshot_b}`",
        f"- Changed sections: `{len(changes)}`",
        "",
    ]
    if not changes:
        lines.append("No differences found in captured command outputs.")
        return "\n".join(lines)

    rows = [
        [item["key"], item["before_line_count"], item["after_line_count"], item["added_line_count"], item["removed_line_count"]]
        for item in changes
    ]
    lines.append(format_table(["Section", "Before Lines", "After Lines", "Added", "Removed"], rows))
    for item in changes[:5]:
        lines.extend(["", f"## {item['key']}", ""])
        if item["added_sample"]:
            lines.extend(["Added sample:", "```text", "\n".join(item["added_sample"]), "```"])
        if item["removed_sample"]:
            lines.extend(["Removed sample:", "```text", "\n".join(item["removed_sample"]), "```"])
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_ssl_vpn_lan_connections",
    annotations={
        "title": "Get SSL VPN LAN Connections",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_ssl_vpn_lan_connections(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Show current LAN destinations reached by connected SSL-VPN users."""

    monitor_result = await run_ssh_command(validate_readonly_command(READONLY_COMMANDS["ssl_vpn_monitor"]))
    users = parse_ssl_vpn_session_rows(monitor_result.get("stdout", ""))
    user_results = []

    for user in users:
        tunnel_ip = user["tunnel_ip"]
        commands = [
            "diagnose sys session filter clear",
            f"diagnose sys session filter src {tunnel_ip}",
            "diagnose sys session list",
            "diagnose sys session filter clear",
        ]
        try:
            sequence = await run_ssh_command_sequence(commands)
            session_output = sequence[2].get("stdout", "") if len(sequence) >= 3 else ""
            destinations = parse_session_destinations(session_output, tunnel_ip)
        except Exception as exc:
            destinations = []
            user["error"] = str(exc)

        user_results.append(
            {
                **user,
                "destinations": destinations,
            }
        )

    payload = {
        "users": user_results,
        "note": "Destinations are derived from current Fortigate session table entries filtered by SSL-VPN tunnel IP.",
    }

    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = ["# SSL-VPN LAN Connections", ""]
    if not user_results:
        lines.append("No connected SSL-VPN users found.")
        return "\n".join(lines)

    for item in user_results:
        lines.extend(
            [
                f"## {item['user']}",
                "",
                f"- Public IP: `{item['source_ip']}`",
                f"- Tunnel IP: `{item['tunnel_ip']}`",
                f"- Group: `{item['group'] or '-'}`",
                "",
            ]
        )
        if item.get("error"):
            lines.extend([f"Error reading sessions: `{item['error']}`", ""])
            continue
        if not item["destinations"]:
            lines.extend(["No active LAN destinations found in the current session table.", ""])
            continue
        rows = [
            [
                dest["destination_ip"],
                dest["destination_port"],
                dest["protocol"] or "-",
                dest["session_count"],
            ]
            for dest in item["destinations"]
        ]
        lines.append(format_table(["Destination IP", "Port", "Proto", "Sessions"], rows))
        lines.append("")

    return "\n".join(lines)


@mcp.tool(
    name="fortigate_trace_session",
    annotations={
        "title": "Trace Fortigate Session",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_trace_session(
    src_ip: OptionalIpAddressParam = None,
    dst_ip: OptionalIpAddressParam = None,
    src_port: PortParam = None,
    dst_port: PortParam = None,
    protocol: ProtocolParam = None,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Inspect current Fortigate session-table entries for a bounded connection filter.

    Use this to follow live connections, confirm policy IDs, NAT/session state, and routing hooks.
    At least one IP address is required; optional port and protocol filters narrow the session lookup.
    The tool clears only the temporary CLI session filter before and after listing sessions.
    """

    if not src_ip and not dst_ip:
        return "Error: provide at least src_ip or dst_ip to avoid broad session-table scans."

    commands = ["diagnose sys session filter clear"]
    filters: dict[str, Any] = {}
    if src_ip:
        parsed = parse_ipv4(src_ip, "Source IP")
        commands.append(f"diagnose sys session filter src {parsed}")
        filters["src_ip"] = str(parsed)
    if dst_ip:
        parsed = parse_ipv4(dst_ip, "Destination IP")
        commands.append(f"diagnose sys session filter dst {parsed}")
        filters["dst_ip"] = str(parsed)
    if src_port:
        commands.append(f"diagnose sys session filter sport {src_port}")
        filters["src_port"] = src_port
    if dst_port:
        commands.append(f"diagnose sys session filter dport {dst_port}")
        filters["dst_port"] = dst_port
    if protocol is not None:
        commands.append(f"diagnose sys session filter proto {protocol}")
        filters["protocol"] = protocol
    commands.extend(["diagnose sys session list", "diagnose sys session filter clear"])

    try:
        sequence = await run_ssh_command_sequence(commands)
    except Exception as exc:
        return format_error(exc)

    session_output = sequence[-2].get("stdout", "") if len(sequence) >= 2 else ""
    summary = summarize_session_trace(session_output)
    payload = {
        "filters": filters,
        **summary,
        "raw_output": trim_output(session_output),
        "commands_run": [result["command"] for result in sequence],
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = [
        "# Session Trace",
        "",
        f"- Filters: `{json.dumps(filters, ensure_ascii=False)}`",
        f"- Sessions found: `{summary['session_count']}`",
        f"- Policy IDs: `{', '.join(summary['policy_ids']) if summary['policy_ids'] else '-'}`",
        "",
    ]
    if not summary["evidence_lines"]:
        lines.append("No matching sessions found in the current session table.")
        return "\n".join(lines)

    lines.extend(["## Evidence", "", "```text"])
    lines.extend(summary["evidence_lines"])
    lines.append("```")
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_search_logs",
    annotations={
        "title": "Search Fortigate Logs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_search_logs(
    category: LogCategoryParam = LogCategory.EVENT,
    field: LogFieldParam = None,
    value: LogValueParam = None,
    view_lines: LogViewLinesParam = 100,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Search recent Fortigate logs with bounded `execute log` filters.

    Use this for read-only troubleshooting of authentication, VPN, traffic, UTM, and system events.
    The command scope is intentionally narrow: one optional field/value filter and at most 500 displayed lines.
    """

    if (field is None) != (value is None):
        return "Error: field and value must be provided together, or both omitted."

    commands = [
        f"execute log filter category {category.value}",
        f"execute log filter view-lines {view_lines}",
    ]
    if field and value:
        commands.append(f"execute log filter field {field.value} {value}")
    commands.append("execute log display")

    try:
        results = await run_ssh_command_sequence(commands)
    except Exception as exc:
        return format_error(exc)

    log_access_errors = detect_log_access_error(results)
    log_output = results[-1].get("stdout", "") if results else ""
    events = parse_fortigate_log_lines(log_output)
    payload = {
        "category": category.value,
        "field": field.value if field else None,
        "value": value,
        "view_lines": view_lines,
        "log_accessible": not log_access_errors,
        "log_access_errors": log_access_errors,
        "events": events[:view_lines],
        "events_parsed": len(events),
        "commands_run": [result["command"] for result in results],
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = [
        "# Log Search",
        "",
        f"- Category: `{category.value}`",
        f"- Filter: `{field.value}={value}`" if field and value else "- Filter: `(none)`",
        f"- View lines: `{view_lines}`",
        f"- Log accessible: `{str(not log_access_errors).lower()}`",
        f"- Events parsed: `{len(events)}`",
        "",
    ]
    if log_access_errors:
        lines.extend(["## Log Access Errors", ""])
        lines.extend([f"- `{line}`" for line in log_access_errors])
        return "\n".join(lines)

    if not events:
        lines.append("No parseable Fortigate key=value log entries were returned.")
        return "\n".join(lines)

    rows = [
        [
            event.get("date", ""),
            event.get("time", ""),
            event.get("type", ""),
            event.get("subtype", ""),
            event.get("level", ""),
            event.get("action", ""),
            event.get("user", ""),
            event.get("srcip", "") or event.get("remip", ""),
            event.get("dstip", ""),
            event.get("status", ""),
            event.get("logdesc", "") or event.get("msg", ""),
        ]
        for event in events[: min(view_lines, 50)]
    ]
    lines.append(format_table(["Date", "Time", "Type", "Subtype", "Level", "Action", "User", "Src", "Dst", "Status", "Description"], rows))
    if len(events) > 50:
        lines.append("")
        lines.append(f"Showing first 50 parsed events. Use JSON output for up to {view_lines} events.")
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_search_traffic_logs",
    annotations={
        "title": "Search Fortigate Traffic Logs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_search_traffic_logs(
    field: LogFieldParam = None,
    value: LogValueParam = None,
    view_lines: LogViewLinesParam = 100,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Search bounded traffic logs by fields such as srcip, dstip, policyid, service, action, or dstport.

    Use this to confirm whether traffic matched a policy, was accepted/denied, and how NAT was applied.
    """

    return await fortigate_search_logs(LogCategory.TRAFFIC, field, value, view_lines, response_format)


@mcp.tool(
    name="fortigate_sniff_packets",
    annotations={
        "title": "Sniff Fortigate Packets",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def fortigate_sniff_packets(
    packet_filter: SnifferFilterParam,
    interface: SnifferInterfaceParam = "any",
    verbosity: SnifferVerbosityParam = 4,
    count: SnifferCountParam = 10,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Run a tightly bounded packet sniffer with a mandatory BPF-style filter and packet count.

    This is read-only but higher impact than `show`/`get` commands. Keep filters narrow, counts low, and use it only for active troubleshooting.
    """

    command = f"diagnose sniffer packet {interface} '{packet_filter}' {verbosity} {count} a"
    return await execute_readonly(command, response_format)


@mcp.tool(
    name="fortigate_get_recent_errors",
    annotations={
        "title": "Get Fortigate Recent Errors",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_recent_errors(
    view_lines: LogViewLinesParam = 300,
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Review recent event logs and summarize warning/error/failure patterns.

    Use this as a first troubleshooting step when the user asks what is failing now.
    It reads bounded event logs only and highlights errors by subtype, source, destination, and status.
    """

    commands = [
        "execute log filter category event",
        f"execute log filter view-lines {view_lines}",
        "execute log display",
    ]
    try:
        results = await run_ssh_command_sequence(commands)
    except Exception as exc:
        return format_error(exc)

    log_access_errors = detect_log_access_error(results)
    events = parse_fortigate_log_lines(results[-1].get("stdout", "") if results else "")
    error_events = [event for event in events if event_is_error_like(event)]
    payload = {
        "events_scanned": len(events),
        "error_like_events": len(error_events),
        "log_accessible": not log_access_errors,
        "log_access_errors": log_access_errors,
        "by_subtype": summarize_events_by_field(error_events, "subtype"),
        "by_status": summarize_events_by_field(error_events, "status"),
        "by_source": summarize_events_by_field(error_events, "srcip"),
        "events": error_events[:50],
    }
    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = [
        "# Recent Errors",
        "",
        f"- Log accessible: `{str(not log_access_errors).lower()}`",
        f"- Events scanned: `{len(events)}`",
        f"- Error-like events: `{len(error_events)}`",
        "",
    ]
    if log_access_errors:
        lines.extend(["## Log Access Errors", ""])
        lines.extend([f"- `{line}`" for line in log_access_errors])
        return "\n".join(lines)
    if not error_events:
        lines.append("No warning/error/failure-like events found in the scanned event logs.")
        return "\n".join(lines)

    rows = [
        [
            event.get("date", ""),
            event.get("time", ""),
            event.get("subtype", ""),
            event.get("level", ""),
            event.get("action", ""),
            event.get("status", ""),
            event.get("srcip", "") or event.get("remip", ""),
            event.get("dstip", ""),
            event.get("msg", "") or event.get("logdesc", ""),
        ]
        for event in error_events[:40]
    ]
    lines.append(format_table(["Date", "Time", "Subtype", "Level", "Action", "Status", "Src/Peer", "Dst", "Message"], rows))
    return "\n".join(lines)


@mcp.tool(
    name="fortigate_get_auth_attack_summary",
    annotations={
        "title": "Get Auth Attack Summary",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def fortigate_get_auth_attack_summary(
    response_format: ResponseFormatParam = ResponseFormat.MARKDOWN,
) -> str:
    """Review recent event logs for admin/SSL-VPN username-password failures."""

    commands = [
        "execute log filter category event",
        "execute log filter view-lines 200",
        "execute log display",
    ]
    try:
        results = await run_ssh_command_sequence(commands)
    except Exception as exc:
        return format_error(exc)

    log_access_errors = detect_log_access_error(results)
    log_output = results[-1].get("stdout", "") if results else ""
    events = parse_fortigate_log_lines(log_output)
    summary = summarize_auth_events(events)
    payload = {
        **summary,
        "events_scanned": len(events),
        "log_accessible": not log_access_errors,
        "log_access_errors": log_access_errors,
        "log_scope": "Most recent event logs returned by Fortigate CLI, up to 200 lines.",
    }

    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = [
        "# Auth Attack Summary",
        "",
        f"- Log accessible: `{str(not log_access_errors).lower()}`",
        f"- Events scanned: `{len(events)}`",
        f"- Admin/SSL-VPN auth failures found: `{summary['auth_failure_count']}`",
        f"- IPsec negotiation failures found: `{summary['ipsec_failure_count']}`",
        "",
    ]
    if log_access_errors:
        lines.extend(
            [
                "## Log Access",
                "",
                "The Fortigate CLI did not return readable event logs for `execute log` commands. "
                "This usually means the Fortigate admin profile does not permit local log reads, "
                "even though the MCP allowlist only permits read-oriented log commands.",
                "",
                "Observed CLI messages:",
                "",
            ]
        )
        lines.extend([f"- `{line}`" for line in log_access_errors])
        lines.extend(
            [
                "",
                "Recommended alternatives: use a Fortigate admin profile that can read logs, "
                "or query FortiAnalyzer/syslog/SIEM for authentication failures.",
                "",
            ]
        )
    if summary["auth_failures_by_source"]:
        lines.extend(["## Auth Failures By Source", ""])
        rows = [[source, count] for source, count in summary["auth_failures_by_source"].items()]
        lines.append(format_table(["Source", "Failures"], rows))
        lines.append("")
    if summary["auth_failures_by_user"]:
        lines.extend(["## Auth Failures By User", ""])
        rows = [[user, count] for user, count in summary["auth_failures_by_user"].items()]
        lines.append(format_table(["User", "Failures"], rows))
        lines.append("")
    if summary["ipsec_failures_by_peer"]:
        lines.extend(["## IPsec Negotiation Failures", ""])
        rows = [[peer, count] for peer, count in summary["ipsec_failures_by_peer"].items()]
        lines.append(format_table(["Peer", "Failures"], rows))
        lines.append("")
    if summary["successful_admin_logins"]:
        lines.extend(["## Recent Successful Admin Logins", ""])
        rows = [
            [
                event.get("date", ""),
                event.get("time", ""),
                event.get("user", ""),
                event.get("method", ""),
                event.get("srcip", ""),
                event.get("ui", ""),
            ]
            for event in summary["successful_admin_logins"]
        ]
        lines.append(format_table(["Date", "Time", "User", "Method", "Source", "UI"], rows))
    return "\n".join(lines)


def main() -> None:
    """Run the Fortigate MCP server over stdio."""

    try:
        mcp.run()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
