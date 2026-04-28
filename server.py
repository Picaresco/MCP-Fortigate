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
    "arp": "get system arp",
    "dns": "get system dns",
    "ntp": "get system ntp",
    "ha_status": "get system ha status",
    "sessions_summary": "get system session status",
    "firewall_policies": "show firewall policy",
    "address_objects": "show firewall address",
    "service_objects": "show firewall service custom",
    "vip_objects": "show firewall vip",
    "static_routes": "show router static",
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
    re.compile(r"^show\s+system\s+(interface|admin|global|accprofile)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+firewall\s+(policy|address|addrgrp|service\s+custom|service\s+group|vip|vipgrp)(?:\s+\d+)?$"),
    re.compile(r"^show\s+router\s+static(?:\s+\d+)?$"),
    re.compile(r"^get\s+vpn\s+ipsec\s+tunnel\s+summary$"),
    re.compile(r"^get\s+vpn\s+ssl\s+monitor$"),
    re.compile(r"^show\s+vpn\s+ssl\s+(settings|web\s+portal)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+vpn\s+ipsec\s+(phase1-interface|phase1|phase2-interface|phase2)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+endpoint-control\s+fctems(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+firewall\s+(access-proxy|proxy-policy)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^show\s+user\s+(local|group)(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^diagnose\s+sys\s+(top-summary|session\s+stat)$"),
    re.compile(r"^diagnose\s+sys\s+session\s+(list|filter\s+(clear|src\s+\d{1,3}(?:\.\d{1,3}){3}))$"),
    re.compile(r"^diagnose\s+netlink\s+interface\s+list(?:\s+[A-Za-z0-9_.:-]+)?$"),
    re.compile(r"^diagnose\s+ip\s+(arp\s+list|route\s+list)$"),
    re.compile(r"^execute\s+log\s+filter\s+(clear|reset|category\s+event|field\s+(subtype|action|user|srcip|status)\s+[A-Za-z0-9_.:@*-]+|view-lines\s+(?:[1-9]\d?|1\d\d|200))$"),
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


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


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


def format_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Build a markdown table."""

    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(value).replace("\n", " ") for value in row) + " |")
    return "\n".join(lines)


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
                "allowed_roots": ["get", "show", "diagnose"],
                "diagnose_scope": "Only explicitly allowlisted diagnostic read commands.",
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
    results = await run_ssh_command_sequence(commands)
    log_output = results[-1].get("stdout", "") if results else ""
    events = parse_fortigate_log_lines(log_output)
    summary = summarize_auth_events(events)
    payload = {
        **summary,
        "events_scanned": len(events),
        "log_scope": "Most recent event logs returned by Fortigate CLI, up to 200 lines.",
    }

    if response_format == ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False)

    lines = [
        "# Auth Attack Summary",
        "",
        f"- Events scanned: `{len(events)}`",
        f"- Admin/SSL-VPN auth failures found: `{summary['auth_failure_count']}`",
        f"- IPsec negotiation failures found: `{summary['ipsec_failure_count']}`",
        "",
    ]
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
