# 🔒 Auditoría de Código y Parcheo Automático

Sistema de escaneo de vulnerabilidades que identifica fallos lógicos, inyecciones y problemas de seguridad que SAST tradicionales suelen pasar por alto. Genera parches específicos para cada vulnerabilidad.

## ✨ Características

- **🔍 Detección avanzada**: Identifica vulnerabilidades complejas mediante razonamiento contextual
- **🔧 Generación de parches**: Propone código específico para solucionar problemas
- **🤖 Auto-fix**: Aplica correcciones automáticas cuando es seguro hacerlo
- **📊 Reportes detallados**: Markdown y JSON con CWEs y recomendaciones
- **🧠 Análisis AST**: Detecta fallos lógicos en flujos de autenticación

## 🚀 Instalación

```bash
cd auditoria-codigo-parcheo
pip install -r requirements.txt
```

## 📋 Requisitos

```
Python 3.8+
```

## 🎯 Uso

### Escaneo básico

```bash
python security-audit.py ./mi-proyecto
```

### Escaneo con generación de parches

```bash
python security-audit.py ./mi-proyecto --generate-patches -o mi-reporte
```

### Reporte JSON

```bash
python security-audit.py ./mi-proyecto --format json
```

## 🔍 Vulnerabilidades Detectadas

| ID | Vulnerabilidad | Severidad | CWE | Auto-fix |
|----|---------------|-----------|-----|----------|
| SEC-001 | SQL Injection | 🔴 Critical | CWE-89 | ✅ Sí |
| SEC-002 | Hardcoded Credentials | 🔴 Critical | CWE-798 | ❌ No |
| SEC-003 | Insecure Deserialization | 🟠 High | CWE-502 | ✅ Sí |
| SEC-004 | Command Injection | 🔴 Critical | CWE-78 | ✅ Sí |
| SEC-005 | Weak Hashing | 🟡 Medium | CWE-916 | ✅ Sí |
| SEC-006 | Debug Mode Enabled | 🟡 Medium | CWE-489 | ✅ Sí |
| SEC-007 | Insecure Random | 🟡 Medium | CWE-338 | ✅ Sí |
| SEC-008 | Eval Usage | 🔴 Critical | CWE-95 | ❌ No |
| SEC-010 | Exception Handling | 🟡 Medium | CWE-396 | ❌ No |

## 📄 Ejemplo de Reporte

```markdown
# 🔒 Reporte de Auditoría de Seguridad

**Total de vulnerabilidades:** 5

## Resumen por Severidad
- 🔴 **CRITICAL**: 2
- 🟠 **HIGH**: 1
- 🟡 **MEDIUM**: 2
- 🟢 **LOW**: 0

## Detalles de Vulnerabilidades

### 🔴 SEC-001: SQL Injection
- **Severidad:** CRITICAL
- **Archivo:** `app.py:45`
- **CWE:** CWE-89
- **Auto-fix:** ✅ Sí

**Código:**
```python
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
```

**Parche sugerido:**
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```
```

## 🔧 Estructura de Parches

```
patches/
├── SEC-001_app.patch
├── SEC-003_utils.patch
└── SEC-004_main.patch
```

## 📊 Integración CI/CD

```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
      - run: pip install -r requirements.txt
      - run: python security-audit.py . --generate-patches
      - uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.md
```

## 🛠️ Extensión

Puedes agregar nuevas reglas en `SecurityAuditor._load_security_rules()`:

```python
{
    "id": "SEC-020",
    "name": "Mi Nueva Regla",
    "pattern": r'expresion_regular_aqui',
    "description": "Descripción de la vulnerabilidad",
    "severity": Severity.HIGH,
    "cwe": "CWE-XXX",
    "auto_fixable": True,
    "fix_template": "codigo_corregido_aqui"
}
```

## 🔄 Flujo de Trabajo

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Código    │───▶│    Scan      │───▶│  Detección  │
│  Fuente     │    │  Vulns       │    │             │
└─────────────┘    └──────────────┘    └──────┬──────┘
                                              │
                    ┌──────────────────────────┼──────────┐
                    ▼                          ▼          ▼
            ┌────────────┐             ┌──────────┐ ┌────────┐
            │ Auto-fix?  │───No───────▶│ Reporte  │ │ Manual │
            └─────┬──────┘             │ Markdown │ │ Review │
                  │Yes                 └──────────┘ └────────┘
                  ▼
            ┌────────────┐
            │  Parche    │
            │ Generado   │
            └────────────┘
```

## 📈 Métricas

El sistema calcula:
- Score de seguridad
- Distribución de severidad
- Vulnerabilidades auto-fixables vs manuales
- CWEs más frecuentes

## 🛡️ Mejores Prácticas

1. **Ejecutar en pre-commit**: `python security-audit.py .`
2. **Revisar parches antes de aplicar**: Siempre verificar cambios automáticos
3. **Actualizar reglas**: Mantener al día con nuevas vulnerabilidades
4. **Integrar en CI/CD**: Bloquear merges con vulnerabilidades críticas

## 📄 Licencia

MIT License
