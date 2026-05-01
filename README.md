![Fortigate MCP banner](assets/banner.png)

# Fortigate MCP

Servidor MCP local para consultar Fortigate por SSH en modo solo lectura.

Pensado para FortiOS 7.4+ y para usarse desde Codex y Claude Desktop mediante transporte `stdio`.

Tambien puede usarse desde cualquier cliente compatible con MCP local por `stdio`, como Cursor, VS Code con GitHub Copilot, Visual Studio con GitHub Copilot Agent Mode, Claude Code y otros clientes MCP.

## Seguridad

Este MCP no ejecuta comandos libres. Todas las herramientas son read-only y el comando manual `fortigate_run_readonly_command` valida una allowlist estricta.

Bloquea tokens como `config`, `edit`, `set`, `unset`, `delete`, `purge`, `reboot`, `shutdown`, `restore`, `factoryreset`, `format` y `debug`.

El token `execute` tambien esta bloqueado por defecto, salvo una excepcion estricta para comandos de lectura de logs (`execute log filter ...` y `execute log display`). Aun asi, un perfil read-only del propio Fortigate puede rechazar esos comandos; en ese caso la herramienta de resumen de ataques indicara que los logs no son accesibles.

Las busquedas de logs estan limitadas a filtros acotados y a un maximo de 500 lineas para reducir impacto. No se permiten acciones de borrado, backup, flush o cambios de configuracion.

La captura de paquetes (`fortigate_sniff_packets`) requiere filtro obligatorio, limita la captura a 20 paquetes y no activa `debug flow`.

La seguridad real debe reforzarse tambien en el Fortigate usando un usuario con perfil de solo lectura.

## Instalacion

Uso recomendado para clientes MCP:

```powershell
uvx fortigate-mcp@latest
```

`uvx` ejecuta el servidor en un entorno aislado gestionado por uv y permite usar la ultima version publicada sin crear una venv manual.

Para fijar una version concreta en entornos donde quieras reproducibilidad:

```powershell
uvx fortigate-mcp@0.2.1
```

Instalacion local para desarrollo desde el repositorio:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item fortigate.config.example.json fortigate.config.json
```

Tambien se puede instalar de forma persistente con pip:

```powershell
python -m pip install --upgrade fortigate-mcp
```

Edita `fortigate.config.json`:

```json
{
  "fortigate": {
    "host": "192.168.1.1",
    "port": 22,
    "username": "admin",
    "password": "change-me",
    "timeout": 15,
    "banner_timeout": 15,
    "auth_timeout": 15,
    "look_for_keys": false,
    "allow_agent": false,
    "disabled_algorithms": {}
  }
}
```

`fortigate.config.json` esta ignorado por Git.

## Herramientas MCP

- `fortigate_list_allowed_commands`
- `fortigate_get_system_status`
- `fortigate_get_interfaces`
- `fortigate_get_routes`
- `fortigate_lookup_route_for_ip`
- `fortigate_get_policy_routes`
- `fortigate_get_firewall_policies`
- `fortigate_get_local_in_policy`
- `fortigate_get_ipsec_vpns`
- `fortigate_get_ssl_vpn_users`
- `fortigate_get_ssl_vpn_lan_connections`
- `fortigate_trace_session`
- `fortigate_search_logs`
- `fortigate_search_traffic_logs`
- `fortigate_sniff_packets`
- `fortigate_get_recent_errors`
- `fortigate_get_auth_attack_summary`
- `fortigate_run_audit_readonly`
- `fortigate_get_public_exposure`
- `fortigate_get_nat_overview`
- `fortigate_get_proxy_policy_overview`
- `fortigate_find_policy_by_ip`
- `fortigate_find_policy_for_flow`
- `fortigate_explain_flow`
- `fortigate_get_policy_risk_summary`
- `fortigate_get_security_profiles_overview`
- `fortigate_get_traffic_controls`
- `fortigate_get_admin_access_surface`
- `fortigate_get_interface_health`
- `fortigate_get_vpn_overview`
- `fortigate_get_vpn_error_summary`
- `fortigate_get_sdwan_status`
- `fortigate_get_dynamic_routing_status`
- `fortigate_get_external_attack_surface`
- `fortigate_export_readonly_snapshot`
- `fortigate_compare_snapshots`
- `fortigate_run_readonly_command`

## Ejemplos de uso

Los siguientes ejemplos son ficticios y solo muestran el tipo de preguntas que puedes hacer desde un agente compatible con MCP.

### Diagnostico general

**Peticion**

```text
Hazme un diagnostico basico del Fortigate.
```

**Respuesta de ejemplo**

```text
Fortigate FG-80F / FortiOS 7.4.x

Estado general:
- Uptime: 128 dias
- CPU: 4%
- Memoria: 58%
- Sesiones activas: 8.421
- Modo: NAT

Observaciones:
- Rendimiento estable.
- No se observan interfaces fisicas con errores relevantes.
- Hay 2 tuneles IPsec caidos que conviene revisar.
```

### Tuneles IPsec

**Peticion**

```text
Listame las conexiones IPsec con entidades externas y dime cuales estan caidas.
```

**Respuesta de ejemplo**

```text
Tuneles IPsec:

| Nombre              | Peer publico    | Estado | Observacion                  |
|---------------------|-----------------|--------|------------------------------|
| vpn-acme-main       | 203.0.113.10    | UP     | Trafico reciente             |
| vpn-partner-backup  | 198.51.100.25   | DOWN   | Sin fase 2 activa            |
| vpn-datacenter      | 203.0.113.80    | UP     | Estable                      |

Resumen: 2 tuneles activos, 1 tunel caido.
```

### Usuarios SSL-VPN

**Peticion**

```text
Que usuarios estan conectados ahora por VPN y a que equipos internos acceden?
```

**Respuesta de ejemplo**

```text
Usuarios SSL-VPN conectados:

| Usuario       | IP VPN        | Origen publico | Destinos LAN observados       |
|---------------|---------------|----------------|-------------------------------|
| ana.garcia    | 10.212.10.14  | 198.51.100.44  | 10.10.20.15:3389              |
| soporte.n1    | 10.212.10.18  | 203.0.113.52   | 10.10.30.20:443, 10.10.30.5:22 |

Nota: la vista se basa en sesiones activas observadas en el Fortigate.
```

### Exposicion publica

**Peticion**

```text
Muestrame que servicios internos estan publicados hacia Internet.
```

**Respuesta de ejemplo**

```text
Exposicion publica detectada:

| VIP              | IP publica     | Destino interno | Servicio |
|------------------|----------------|-----------------|----------|
| vip-portal       | 203.0.113.120  | 10.10.40.10     | HTTPS    |
| vip-rdp-soporte  | 203.0.113.121  | 10.10.50.25     | RDP      |

Recomendacion:
- Revisar si RDP debe seguir expuesto publicamente.
- Aplicar restricciones por origen si el servicio es necesario.
```

### Ataques de usuario y contrasena

**Peticion**

```text
Tenemos ataques de usuario y contrasena contra el Fortigate?
```

**Respuesta de ejemplo**

```text
Resumen de autenticacion reciente:

- SSL-VPN: 37 fallos de login en la ultima hora.
- Administracion HTTPS/SSH: sin fallos relevantes.
- IPs con mas intentos:
  - 198.51.100.200: 22 intentos
  - 203.0.113.77: 9 intentos

Posible fuerza bruta contra SSL-VPN.
```

### Busqueda de logs

**Peticion**

```text
Busca eventos recientes de VPN con status failure.
```

**Respuesta de ejemplo**

```text
Log Search

- Category: event
- Filter: status=failure
- Events parsed: 14

| Date       | Time     | Type  | Subtype | Action | Src          | Status  | Description |
|------------|----------|-------|---------|--------|--------------|---------|-------------|
| 2026-05-01 | 11:42:10 | event | vpn     | tunnel | 203.0.113.10 | failure | IPsec phase 1 negotiation failed |
```

### Seguimiento de sesiones

**Peticion**

```text
Mira si hay sesiones desde 10.212.10.14 hacia 10.10.20.15 por RDP.
```

**Respuesta de ejemplo**

```text
Session Trace

- Filters: {"src_ip": "10.212.10.14", "dst_ip": "10.10.20.15", "dst_port": 3389, "protocol": 6}
- Sessions found: 2
- Policy IDs: 42

Evidence:
- session info: proto=6 ...
- 10.212.10.14:55122->10.10.20.15:3389 ...
- policy_id=42 ...
```

### Logs de trafico

**Peticion**

```text
Busca logs de trafico recientes hacia 79.148.246.79.
```

**Respuesta de ejemplo**

```text
Log Search

- Category: traffic
- Filter: dstip=79.148.246.79
- Events parsed: 5

| Date       | Time     | Action | Src        | Dst          | Description       |
|------------|----------|--------|------------|--------------|-------------------|
| 2026-05-01 | 21:47:09 | close  | 10.0.0.106 | 79.148.246.79|                   |
```

### Captura acotada

**Peticion**

```text
Haz una captura de 5 paquetes para host 10.0.0.57 y puerto 22.
```

**Respuesta de ejemplo**

```text
Fortigate Command Result

- Command: diagnose sniffer packet any 'host 10.0.0.57 and port 22' 4 5 a

2026-05-01 19:47:30 ssl.root in 10.212.134.100.22467 -> 10.0.0.57.22
```

### Lookup de ruta

**Peticion**

```text
Por donde saldria el Fortigate para llegar a 10.20.30.40?
```

**Respuesta de ejemplo**

```text
Route Lookup

| Network       | Interface | Gateway     | Code | Distance | Metric |
|---------------|-----------|-------------|------|----------|--------|
| 10.20.30.0/24 | ipsec-acme| -           | S    | 10       | 0      |
```

### Policy routes y NAT

**Peticion**

```text
Revisa si hay policy routes o NAT que puedan afectar al trafico.
```

**Respuesta de ejemplo**

```text
Policy routes:
- config router policy / end

NAT Overview:
- VIP objects: 73
- NAT policies: 67
- Central SNAT: sin entradas
```

### Proxy, UTM y controles de trafico

**Peticion**

```text
Comprueba si proxy, perfiles de seguridad, DoS o shapers pueden afectar al trafico.
```

**Respuesta de ejemplo**

```text
Proxy Policy Overview:
- proxy-policy ZTNA_ALLOW
- access-proxy RDP

Security Profiles Overview:
- Politicas con AV/IPS/WebFilter/AppCtrl/SSL inspection

Traffic Controls:
- DoS-policy
- traffic-shaper
- per-ip-shaper
```

### Errores recientes

**Peticion**

```text
Dime que errores recientes ves en el Fortigate.
```

**Respuesta de ejemplo**

```text
Recent Errors

- Events scanned: 50
- Error-like events: 10

| Date       | Time     | Subtype | Level   | Status          | Src/Peer    | Message             |
|------------|----------|---------|---------|-----------------|-------------|---------------------|
| 2026-05-01 | 21:34:07 | vpn     | error   | negotiate_error | 80.58.157.1 | IPsec phase 1 error |
| 2026-05-01 | 21:34:02 | endpoint| warning |                 |             | EMS certificate error |
```

### Politica candidata para un flujo

**Peticion**

```text
Que politicas podrian permitir 10.212.10.14 hacia 10.0.0.57 por SSH?
```

**Respuesta de ejemplo**

```text
Policy Lookup For Flow

- Flow: 10.212.10.14 -> 10.0.0.57 protocol 6 dst_port 22
- Best route interface: internal
- Candidate policies: 2

| ID | Name      | Src Intf | Dst Intf | Src Match          | Dst Match   | Service |
|----|-----------|----------|----------|--------------------|-------------|---------|
| 2  | VPN->LAN  | ssl.root | internal | SSLVPN_TUNNEL_ADDR | 10.0.0.0/24 | ALL     |
```

### Explicacion completa de un flujo

**Peticion**

```text
Explica el flujo 10.212.134.100 hacia 10.0.0.57 por TCP/22.
```

**Respuesta de ejemplo**

```text
Flow Explanation

- Destination route: 10.0.0.0/24 via internal
- Candidate policies: 2
- Active sessions: 1
- Traffic log matches: 0

Candidate Policies:
- policy 63 VPN-NUNSYS --> LAN
- policy 2 VPN --> LAN

Active Session Evidence:
- policy_id=2
- 10.212.134.100:32889 -> 10.0.0.57:22
```

### Superficie administrativa

**Peticion**

```text
Audita como se administra el Fortigate y si hay accesos peligrosos.
```

**Respuesta de ejemplo**

```text
Admin Access Surface

| Interface | IP             | Allowaccess | WAN-like | Risky |
|-----------|----------------|-------------|----------|-------|
| wan1      | 192.0.2.10/24  | ping, fgfm  | yes      | -     |

| Admin  | Profile     | No Trusthost | 2FA |
|--------|-------------|--------------|-----|
| claude | SoloLectura | yes          | -   |
```

### Superficie externa

**Peticion**

```text
Resume todo lo expuesto hacia fuera en el Fortigate.
```

**Respuesta de ejemplo**

```text
External Attack Surface

- WAN-like interfaces con allowaccess
- VIPs/DNAT publicados y politicas asociadas
- SSL-VPN: puerto, interfaces, origenes y pools
- IPsec peers y remote gateways
- Proxy/ZTNA publicado
- Local-in policy
```

### Riesgo de politicas

**Peticion**

```text
Resume las politicas amplias o con logging mejorable.
```

**Respuesta de ejemplo**

```text
Policy Risk Summary

- Policies parsed: 143
- Policies with findings: 126

| ID | Name      | Src Addr | Dst Addr | Service | Issues                         |
|----|-----------|----------|----------|---------|--------------------------------|
| 4  | LAN->WAN  | all      | all      | ALL     | srcaddr all; dstaddr all; service ALL |
```

### SD-WAN

**Peticion**

```text
Revisa el estado de SD-WAN y sus SLA.
```

**Respuesta de ejemplo**

```text
SD-WAN Status

- Health-checks: alive/dead, packet-loss, latency, jitter y SLA map.
- Services: miembros seleccionados por regla SD-WAN.
- Configuracion: miembros, gateways, health-checks y servicios.
```

### Comparacion de snapshots

**Peticion**

```text
Compara el snapshot inicial con el ultimo y dime que ha cambiado.
```

**Respuesta de ejemplo**

```text
Snapshot Comparison

- Changed sections: 4

| Section              | Added | Removed |
|----------------------|-------|---------|
| ipsec_tunnel_summary | 3     | 3       |
| ssl_vpn_monitor      | 2     | 6       |
```

### Auditoria read-only

**Peticion**

```text
Haz una auditoria de seguridad del Fortigate y prioriza los hallazgos.
```

**Respuesta de ejemplo**

```text
Hallazgos prioritarios:

1. Firmware pendiente de revision
   - Version observada: FortiOS 7.4.x
   - Accion: comparar con el ultimo release recomendado por Fortinet.

2. Servicios publicados hacia Internet
   - Detectados VIPs con HTTPS y RDP.
   - Accion: validar necesidad, origenes permitidos y logging.

3. Tuneles VPN caidos
   - 1 tunel IPsec sin fase 2 activa.
   - Accion: revisar propuestas y conectividad con el peer.

4. SSL-VPN
   - Usuarios conectados y sesiones LAN activas.
   - Accion: revisar MFA, grupos permitidos y politicas asociadas.
```

## Configuracion para Claude Desktop

Anade este servidor en el JSON de Claude Desktop:

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "uvx",
      "args": [
        "fortigate-mcp@latest"
      ],
      "env": {
        "FORTIGATE_MCP_CONFIG": "C:\\ruta\\segura\\fortigate.config.json"
      }
    }
  }
}
```

Si prefieres ejecutar el `server.py` del repo para desarrollo, usa la venv local:

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "C:\\ruta\\al\\proyecto\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\ruta\\al\\proyecto\\server.py"
      ],
      "env": {
        "FORTIGATE_MCP_CONFIG": "C:\\ruta\\segura\\fortigate.config.json"
      }
    }
  }
}
```

## Configuracion para Codex

Anade este bloque a `%USERPROFILE%\.codex\config.toml`:

```toml
[mcp_servers.fortigate]
command = 'uvx'
args = ['fortigate-mcp@latest']

[mcp_servers.fortigate.env]
FORTIGATE_MCP_CONFIG = 'C:\ruta\segura\fortigate.config.json'
```

## Configuracion para Cursor

Cursor puede cargar servidores MCP desde `.cursor/mcp.json` en el proyecto o desde la configuracion global del usuario.

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "uvx",
      "args": [
        "fortigate-mcp@latest"
      ],
      "env": {
        "FORTIGATE_MCP_CONFIG": "C:\\ruta\\segura\\fortigate.config.json"
      }
    }
  }
}
```

## Configuracion para VS Code

VS Code usa `mcp.json`. Puedes configurarlo a nivel de workspace en `.vscode/mcp.json` o desde la configuracion de usuario.

```json
{
  "servers": {
    "fortigate": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "fortigate-mcp@latest"
      ],
      "env": {
        "FORTIGATE_MCP_CONFIG": "C:\\ruta\\segura\\fortigate.config.json"
      }
    }
  }
}
```

## Configuracion para Visual Studio

Visual Studio 2022 17.14+ y Visual Studio 2026 pueden detectar configuraciones MCP en `%USERPROFILE%\\.mcp.json`, en `<SOLUTIONDIR>\\.mcp.json`, en `.vscode/mcp.json` o en `.cursor/mcp.json`.

Ejemplo de `%USERPROFILE%\\.mcp.json`:

```json
{
  "servers": {
    "fortigate": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "fortigate-mcp@latest"
      ],
      "env": {
        "FORTIGATE_MCP_CONFIG": "C:\\ruta\\segura\\fortigate.config.json"
      }
    }
  }
}
```

## Prueba rapida

Validar sintaxis:

```powershell
.\.venv\Scripts\python.exe -m py_compile server.py
```

Verificar con MCP Inspector:

```powershell
npx @modelcontextprotocol/inspector uvx fortigate-mcp@latest
```
