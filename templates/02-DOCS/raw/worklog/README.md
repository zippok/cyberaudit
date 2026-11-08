# Worklog — Registro Inmutable de Sesiones y Evidencias

Esta carpeta almacena el registro cronológico y las evidencias de cada sesión de trabajo, auditoría o refactorización (`raw/worklog/<YYYY-MM-DD>-<slug>.md`).
Los registros aquí depositados son fuentes en crudo: nunca se modifican a posteriori y sirven como fuente primaria para compilar la wiki del proyecto.

## Estructura de cada entrada de worklog

```yaml
---
type: worklog
title: Título conciso de lo realizado
description: Resumen en una frase de la sesión
timestamp: YYYY-MM-DDTHH:MM:SSZ
topic: topico-inferido
status: unprocessed
sources: []
---
```

### Secciones obligatorias:
- **Qué hicimos:** Cambios concretos y pruebas ejecutadas.
- **Por qué:** Intención, invariantes de ingeniería y decisiones tomadas.
- **Archivos tocados:** `ruta:línea` con descripción del cambio.
- **Resultado / Evidencia:** Salida de tests, estado de escaneo o sello criptográfico emitido.
- **Siguiente paso:** Puntos pendientes para la próxima sesión de trabajo.
