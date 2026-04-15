#!/usr/bin/env python3
"""
Auditoría de Código y Parcheo Automático
Sistema de escaneo de vulnerabilidades con generación de parches
"""

import ast
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import argparse


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity
    file: str
    line: int
    code_snippet: str
    cwe: str
    recommendation: str
    auto_fixable: bool = False
    patch: str = ""


class SecurityAuditor:
    """Escáner de vulnerabilidades con capacidad de generación de parches"""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.vulnerabilities = []
        self.rules = self._load_security_rules()

    def _load_security_rules(self) -> List[Dict]:
        """Carga reglas de detección de vulnerabilidades"""
        return [
            {
                "id": "SEC-001",
                "name": "SQL Injection",
                "pattern": r"execute\s*\(.*[\+\%\%].*\)",
                "description": "Posible inyección SQL por concatenación de strings",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-89",
                "auto_fixable": True,
                "fix_template": "# Usar consultas parametrizadas\ncursor.execute(\"SELECT * FROM table WHERE id = %s\", (user_input,))"
            },
            {
                "id": "SEC-002",
                "name": "Hardcoded Credentials",
                "pattern": r'(password|passwd|pwd|secret|key|token)\s*[=:]\s*["\'][^"\']{4,}["\']',
                "description": "Credenciales hardcodeadas detectadas",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-798",
                "auto_fixable": False
            },
            {
                "id": "SEC-003",
                "name": "Insecure Deserialization",
                "pattern": r'pickle\.loads?\s*\(',
                "description": "Deserialización insegura con pickle",
                "severity": Severity.HIGH,
                "cwe": "CWE-502",
                "auto_fixable": True,
                "fix_template": "# Usar json en lugar de pickle\nimport json\ndata = json.loads(user_input)"
            },
            {
                "id": "SEC-004",
                "name": "Command Injection",
                "pattern": r'(os\.system|subprocess\.call|subprocess\.run)\s*\([^)]*\+',
                "description": "Posible inyección de comandos",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-78",
                "auto_fixable": True,
                "fix_template": "# Usar lista de argumentos en lugar de string\nsubprocess.run(['ls', directory], capture_output=True)"
            },
            {
                "id": "SEC-005",
                "name": "Weak Hashing",
                "pattern": r'(hashlib\.md5|hashlib\.sha1)\s*\(',
                "description": "Algoritmo de hash débil detectado",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-916",
                "auto_fixable": True,
                "fix_template": "# Usar hash seguro\nimport hashlib\nhash = hashlib.sha256(data).hexdigest()"
            },
            {
                "id": "SEC-006",
                "name": "Debug Mode Enabled",
                "pattern": r'(DEBUG|debug)\s*=\s*(True|true)',
                "description": "Modo debug habilitado en producción",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-489",
                "auto_fixable": True,
                "fix_template": "DEBUG = False"
            },
            {
                "id": "SEC-007",
                "name": "Insecure Random",
                "pattern": r'random\.(random|randint|choice)\s*\(',
                "description": "Uso de random para propósitos criptográficos",
                "severity": Severity.MEDIUM,
                "cwe": "CWE-338",
                "auto_fixable": True,
                "fix_template": "# Usar secrets para criptografía\nimport secrets\ntoken = secrets.token_urlsafe(16)"
            },
            {
                "id": "SEC-008",
                "name": "Eval Usage",
                "pattern": r'eval\s*\(',
                "description": "Uso peligroso de eval()",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-95",
                "auto_fixable": False
            }
        ]

    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Escanea un archivo en busca de vulnerabilidades"""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error leyendo {file_path}: {e}")
            return vulnerabilities

        # Escaneo con expresiones regulares
        for rule in self.rules:
            pattern = re.compile(rule["pattern"], re.IGNORECASE)

            for line_num, line in enumerate(lines, 1):
                if pattern.search(line):
                    # Extraer contexto (3 líneas antes y después)
                    start = max(0, line_num - 3)
                    end = min(len(lines), line_num + 3)
                    context = '\n'.join(lines[start:end])

                    vuln = Vulnerability(
                        id=rule["id"],
                        title=rule["name"],
                        description=rule["description"],
                        severity=rule["severity"],
                        file=str(file_path),
                        line=line_num,
                        code_snippet=context.strip(),
                        cwe=rule["cwe"],
                        recommendation=rule.get("fix_template", "Revisar manualmente"),
                        auto_fixable=rule.get("auto_fixable", False),
                        patch=rule.get("fix_template", "")
                    )
                    vulnerabilities.append(vuln)

        # Análisis AST para lógica más compleja
        try:
            tree = ast.parse(content)
            ast_vulns = self._analyze_ast(tree, file_path, lines)
            vulnerabilities.extend(ast_vulns)
        except SyntaxError:
            pass

        return vulnerabilities

    def _analyze_ast(self, tree: ast.AST, file_path: Path, lines: List[str]) -> List[Vulnerability]:
        """Análisis de AST para detectar fallos lógicos complejos"""
        vulnerabilities = []

        for node in ast.walk(tree):
            # Detectar autenticación con contraseña hardcodeada
            if isinstance(node, ast.Compare):
                # Buscar comparaciones de contraseñas
                pass

            # Detectar manejo de excepciones genérico
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    if handler.type is None:  # except:
                        vuln = Vulnerability(
                            id="SEC-010",
                            title="Exception Handling",
                            description="Uso de excepciones genéricas (except:)",
                            severity=Severity.MEDIUM,
                            file=str(file_path),
                            line=handler.lineno,
                            code_snippet=lines[handler.lineno-1].strip(),
                            cwe="CWE-396",
                            recommendation="Capturar excepciones específicas",
                            auto_fixable=False
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def scan_project(self) -> List[Vulnerability]:
        """Escanea todo el proyecto"""
        print(f"🔍 Escaneando proyecto: {self.project_path}")

        for file_path in self.project_path.rglob("*.py"):
            if "__pycache__" in str(file_path) or "venv" in str(file_path):
                continue

            print(f"  📄 {file_path.relative_to(self.project_path)}")
            vulns = self.scan_file(file_path)
            self.vulnerabilities.extend(vulns)

        return self.vulnerabilities

    def generate_patch(self, vulnerability: Vulnerability) -> str:
        """Genera un parche para una vulnerabilidad"""
        if not vulnerability.auto_fixable:
            return "# Requiere revisión manual"

        patch = f"""# Parche para {vulnerability.id}: {vulnerability.title}
# Archivo: {vulnerability.file}
# Línea: {vulnerability.line}

{vulnerability.patch}

# Original (línea {vulnerability.line}):
# {vulnerability.code_snippet.split(chr(10))[0] if vulnerability.code_snippet else 'N/A'}
"""
        return patch

    def apply_patches(self, auto_fixable_only: bool = True) -> Dict[str, str]:
        """Genera archivos de parche para todas las vulnerabilidades"""
        patches = {}

        for vuln in self.vulnerabilities:
            if auto_fixable_only and not vuln.auto_fixable:
                continue

            patch_content = self.generate_patch(vuln)
            patch_file = Path(f"patches/{vuln.id}_{Path(vuln.file).stem}.patch")
            patch_file.parent.mkdir(exist_ok=True)

            with open(patch_file, 'w') as f:
                f.write(patch_content)

            patches[str(patch_file)] = patch_content

        return patches

    def generate_report(self, output_format: str = "markdown") -> str:
        """Genera un reporte de vulnerabilidades"""
        if output_format == "json":
            return json.dumps(
                [{
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "file": v.file,
                    "line": v.line,
                    "cwe": v.cwe,
                    "auto_fixable": v.auto_fixable
                } for v in self.vulnerabilities],
                indent=2
            )

        # Markdown report
        report = ["# 🔒 Reporte de Auditoría de Seguridad\n"]
        report.append(f"**Total de vulnerabilidades:** {len(self.vulnerabilities)}\n")

        # Contar por severidad
        severity_counts = {s: 0 for s in Severity}
        for v in self.vulnerabilities:
            severity_counts[v.severity] += 1

        report.append("## Resumen por Severidad\n")
        for sev, count in severity_counts.items():
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev.value, "⚪")
            report.append(f"- {emoji} **{sev.value.upper()}**: {count}\n")

        report.append("\n## Detalles de Vulnerabilidades\n")

        for vuln in sorted(self.vulnerabilities, key=lambda x: x.severity.value, reverse=True):
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢"
            }.get(vuln.severity.value, "⚪")

            report.append(f"\n### {severity_emoji} {vuln.id}: {vuln.title}\n")
            report.append(f"- **Severidad:** {vuln.severity.value.upper()}\n")
            report.append(f"- **Archivo:** `{vuln.file}:{vuln.line}`\n")
            report.append(f"- **CWE:** {vuln.cwe}\n")
            report.append(f"- **Auto-fix:** {'✅ Sí' if vuln.auto_fixable else '❌ No'}\n")
            report.append(f"\n**Descripción:** {vuln.description}\n")
            report.append(f"\n**Código:**\n```python\n{vuln.code_snippet}\n```\n")

            if vuln.auto_fixable:
                report.append(f"\n**Parche sugerido:**\n```python\n{vuln.patch}\n```\n")

        return ''.join(report)


def main():
    parser = argparse.ArgumentParser(
        description="Auditoría de Código y Parcheo Automático"
    )
    parser.add_argument("path", help="Ruta del proyecto a auditar")
    parser.add_argument(
        "--format", "-f",
        choices=["markdown", "json"],
        default="markdown",
        help="Formato del reporte"
    )
    parser.add_argument(
        "--generate-patches", "-p",
        action="store_true",
        help="Generar archivos de parche"
    )
    parser.add_argument(
        "--output", "-o",
        default="security-report",
        help="Nombre base del archivo de reporte"
    )

    args = parser.parse_args()

    # Ejecutar auditoría
    auditor = SecurityAuditor(args.path)
    vulnerabilities = auditor.scan_project()

    print(f"\n🔴 {len(vulnerabilities)} vulnerabilidad(es) encontrada(s)\n")

    # Generar reporte
    report = auditor.generate_report(args.format)
    report_file = f"{args.output}.{args.format.replace('markdown', 'md')}"

    with open(report_file, 'w') as f:
        f.write(report)

    print(f"📄 Reporte guardado: {report_file}")

    # Generar parches
    if args.generate_patches:
        patches = auditor.apply_patches(auto_fixable_only=True)
        print(f"🔧 {len(patches)} parche(s) generado(s) en directorio 'patches/'")


if __name__ == "__main__":
    main()
