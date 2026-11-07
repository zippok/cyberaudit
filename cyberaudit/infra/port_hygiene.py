"""
CyberAudit Port Hygiene and Service Exposure Scanner
Validates the principle of least network exposure on public interfaces:
- Identifies critical ports accidentally exposed to the internet (Databases, In-memory caches, Unencrypted protocols).
- Performs passive, defensive banner inspection without aggressive probes or intrusive fuzzing.
- Maps findings directly to CIS Benchmarks, PCI-DSS, and CWE standards.
"""

import socket
from typing import List, Dict, Tuple, Optional
from cyberaudit.core.models import Finding, Severity, Pillar, StrideCategory


# Dictionary of critical ports: port -> (service_name, category, description, severity, cwe, remediation)
EXPOSED_SERVICE_CATALOG: Dict[int, Tuple[str, str, str, Severity, str, str]] = {
    # Databases
    3306: (
        "MySQL",
        "Database",
        "Base de datos relacional MySQL expuesta directamente a la red pública.",
        Severity.CRITICAL,
        "CWE-200",
        "Cerrar el puerto 3306 en el Security Group/Firewall. Usar un túnel SSH, VPN corporativa o Bastion host.",
    ),
    5432: (
        "PostgreSQL",
        "Database",
        "Base de datos PostgreSQL accesible en interfaz externa sin perímetro.",
        Severity.CRITICAL,
        "CWE-200",
        "Restringir el puerto 5432 exclusivamente a la subred de aplicaciones internas.",
    ),
    27017: (
        "MongoDB",
        "Database",
        "Base de datos NoSQL MongoDB expuesta públicamente (riesgo severo de compromiso/ransomware).",
        Severity.CRITICAL,
        "CWE-200",
        "Habilitar autenticación SCRAM, deshabilitar bindIp 0.0.0.0 y aislar el puerto en una VPC privada.",
    ),
    1433: (
        "Microsoft SQL Server",
        "Database",
        "Instancia MSSQL accesible públicamente.",
        Severity.CRITICAL,
        "CWE-200",
        "Bloquear el puerto 1433 en el firewall y restringir el acceso a hosts autorizados.",
    ),
    9200: (
        "Elasticsearch",
        "Database",
        "Cluster Elasticsearch accesible sin perímetro perimetral.",
        Severity.CRITICAL,
        "CWE-200",
        "Habilitar autenticación básica/TLS en Elasticsearch y restringir el puerto 9200 en el firewall.",
    ),
    # In-memory stores
    6379: (
        "Redis",
        "In-Memory Store",
        "Almacén en memoria Redis accesible públicamente (riesgo de RCE y fuga de datos).",
        Severity.CRITICAL,
        "CWE-200",
        "Configurar bind a 127.0.0.1, activar requirepass/ACLs y cerrar el puerto 6379 hacia internet.",
    ),
    11211: (
        "Memcached",
        "In-Memory Store",
        "Caché Memcached expuesto a internet (fuga de sesiones y vector de amplificación DDoS).",
        Severity.HIGH,
        "CWE-200",
        "Deshabilitar soporte UDP en Memcached y bloquear el puerto 11211 en interfaces públicas.",
    ),
    # Insecure/Plaintext protocols
    21: (
        "FTP",
        "Cleartext Protocol",
        "Servidor FTP en texto claro expuesto a la red pública.",
        Severity.MEDIUM,
        "CWE-319",
        "Migrar a SFTP (SSH File Transfer Protocol) o FTPS con cifrado TLS obligatorio.",
    ),
    23: (
        "Telnet",
        "Cleartext Protocol",
        "Protocolo administrativo Telnet sin cifrado expuesto públicamente.",
        Severity.HIGH,
        "CWE-319",
        "Deshabilitar Telnet inmediatamente y migrar toda la administración a SSHv2.",
    ),
    3389: (
        "RDP (Remote Desktop)",
        "Management Interface",
        "Protocolo de escritorio remoto RDP de Windows expuesto a internet público.",
        Severity.HIGH,
        "CWE-284",
        "Cerrar el puerto 3389 hacia internet. Exigir RD Gateway con MFA o conexión vía VPN corporativa.",
    ),
    5900: (
        "VNC",
        "Management Interface",
        "Servicio de acceso gráfico VNC expuesto sin perímetro.",
        Severity.HIGH,
        "CWE-284",
        "Tunelizar VNC a través de SSH o VPN y cerrar el puerto 5900 en el firewall.",
    ),
}


class PortHygieneAuditor:
    """Defensive scanner for port hygiene and service exposure."""

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def inspect_port(self, host: str, ip: str, port: int) -> Optional[Tuple[bool, str]]:
        """
        Tests TCP connection to a single port and passively grabs banner if open.
        Returns (is_open, banner_str) or None.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((ip, port)) == 0:
                    banner = ""
                    try:
                        sock.sendall(b"\r\n")
                        sock.settimeout(0.5)
                        raw_banner = sock.recv(128)
                        banner = raw_banner.decode("latin-1", errors="ignore").strip()
                    except Exception:
                        pass
                    return True, banner
        except Exception:
            pass
        return None

    def scan_target(
        self,
        host: str,
        resolved_ips: List[str],
        custom_ports: Optional[List[int]] = None,
    ) -> List[Finding]:
        """
        Scans resolved target IPs for insecure exposed services.
        """
        findings: List[Finding] = []
        target_ip = resolved_ips[0] if resolved_ips else host
        ports_to_check = custom_ports if custom_ports else list(EXPOSED_SERVICE_CATALOG.keys())

        for port in ports_to_check:
            if port not in EXPOSED_SERVICE_CATALOG and not custom_ports:
                continue

            service_meta = EXPOSED_SERVICE_CATALOG.get(
                port,
                ("Custom Port", "Generic", f"Puerto {port} accesible públicamente.", Severity.LOW, "CWE-200", "Revisar necesidad de exposición pública.")
            )
            service_name, category, desc, severity, cwe, remediation = service_meta

            result = self.inspect_port(host, target_ip, port)
            if result and result[0]:
                _, banner = result
                banner_detail = f" Banner detectado: '{banner}'" if banner else " (Sin banner detectado)."
                full_desc = f"{desc}{banner_detail}"

                findings.append(Finding(
                    id=f"INFRA-PORT-{port}",
                    title=f"Servicio Inseguro Expuesto: {service_name} (Puerto {port}/TCP)",
                    description=full_desc,
                    severity=severity,
                    pillar=Pillar.CLOUD_DEFENSE,
                    scanner_name="port_hygiene",
                    file_path=f"{host}:{port}",
                    cwe_id=cwe,
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE.value,
                    compliance_controls={
                        "CIS_Controls": "CIS Controls v8 4.1 (Ensure only fully supported network ports are open)",
                        "PCI_DSS": "PCI-DSS 4.0 Req 1.3 (Restricted network traffic)",
                        "ISO_27001": "ISO 27001:2022 A.8.20 (Network Security)",
                    },
                    remediation=remediation,
                    confidence="HIGH",
                ))

        return findings
