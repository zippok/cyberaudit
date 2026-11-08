# Inbox — Ingesta de Datos en Crudo (Karpathy Chaos Engine)

Este es el buzón de entrada de tu base de conocimiento y documentación de proyecto.
Cualquier archivo o dato en crudo que deposites aquí será procesado, clasificado y compilado en la wiki estructurada (`02-DOCS/wiki/`).

> Aquí cae cualquier dato en crudo. No hay formato rígido. El sistema se adapta a tu caos, no al revés.

## Qué puedes depositar aquí

Cualquier documento o evidencia:
- Informes de auditoría, especificaciones, contratos — `*.pdf`
- Capturas de pantalla, diagramas de arquitectura — `*.png`, `*.jpg`
- Payloads, trazas de red, exports de logs — `*.json`, `*.log`
- Hojas de cálculo, métricas de rendimiento — `*.csv`, `*.xlsx`
- Notas de ingeniería, snippets, memos — `*.md`, `*.txt`
- Exportaciones de código y respuestas de API — `*.html`, `*.xml`

## Cómo funciona

1. **Depositas archivos aquí** (o subcarpetas completas).
2. **El agente o CyberAudit ejecuta el barrido:**
   - Detecta el formato y extrae el contenido técnico.
   - Clasifica por tópico inferido (`seguridad/`, `arquitectura/`, `qa/`, `devsecops/`, etc.).
   - Relaciona los conceptos con los artículos existentes en `02-DOCS/wiki/` (enlaces bidireccionales).
   - Genera o actualiza el artículo correspondiente en la wiki.
3. **Los originales en crudo se preservan inmutables** en `02-DOCS/raw/` como evidencia y pista de auditoría.
