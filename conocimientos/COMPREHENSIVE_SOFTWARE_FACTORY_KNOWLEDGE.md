# Base de Conocimiento Integral: Software Factory & CyberAudit
> Síntesis de Ingeniería de Software Moderna, Seguridad de Aplicaciones, Sistemas de Datos y Revisión de Código a Escala.
> Compilado a partir de: *Software Engineering at Google* (Winters et al.), *Modern Software Engineering* (Farley & Gee), *Alice and Bob Learn Application Security* (Tanya Janca), *Designing Data-Intensive Applications 2nd Ed.* (Kleppmann & Riccomini), *Refactoring* (Fowler & Beck), *Code Complete 2nd Ed.* (McConnell) y *AI Engineering* (Chip Huyen).

---

## 1. Axiomas de la Ingeniería de Software Moderna (David Farley)
La ingeniería de software no es mera "producción artesanal de código", sino la aplicación de un **enfoque científico y empírico** al diseño de sistemas computacionales bajo dos pilares obligatorios:

### Pilar A: Optimizar para el Aprendizaje (Fast Feedback & Incrementalism)
1. **Iteración Rápida y Determinista:** Todo cambio debe descomponerse en unidades atómicas que puedan evaluarse en segundos, no horas.
2. **TDD como Especificación de Comportamiento:** Las pruebas unitarias no son para verificar detalles internos de implementación (`private methods` o `spies` frágiles), sino para documentar y garantizar **contratos e invariantes observables**.
3. **Diseño Guiado por Pruebas:** Si un módulo es difícil de probar en aislamiento hermético, es señal empírica irrefutable de que sufre de alto acoplamiento o baja cohesión.
4. **Empirismo contra Dogmatismo:** Las decisiones arquitectónicas no se toman por preferencia estética, sino por métricas observables: cobertura de invariantes, tiempo de ciclo y tasa de fallos en regresión.

### Pilar B: Optimizar para Gestionar la Complejidad
1. **Modularidad:** Módulos autónomos con límites estrictos (*bounded contexts*).
2. **Cohesión:** Las cosas que cambian juntas por la misma razón de negocio deben residir juntas.
3. **Separación de Responsabilidades (SoC):** La lógica de orquestación, la lógica de acceso a datos y las interfaces de presentación deben estar completamente desacopladas.
4. **Ocultamiento de Información (*Information Hiding*):** Los clientes de un módulo nunca deben depender de sus estructuras internas de almacenamiento o formatos de serialización transitoria.
5. **Acoplamiento Débil (*Loose Coupling*):** Dependencia estricta de abstracciones e interfaces, facilitando el reemplazo y testing hermético.

---

## 2. Ingeniería de Software a Escala Google (Titus Winters, Tom Manshreck, Hyrum Wright)

### Ley de Hyrum (Hyrum's Law)
> *"Con un número suficiente de usuarios de una API, no importa lo que prometas en el contrato: todos los comportamientos observables de tu sistema serán dependidos por alguien."*
- **Implicación en la Factory:**
  - Si un agente o endpoint expone detalles accidentales (como el orden de claves en un JSON, tiempos de respuesta o stack traces internos), otros módulos o clientes empezarán a acoplarse a ellos.
  - Las APIs de la Software Factory (WebSockets, REST, endpoints de auditoría) deben tener contratos sellados, normalizados y tipados.

### Shift Left (Mover a la Izquierda)
- El costo de corregir un defecto crece exponencialmente a medida que avanza en el ciclo de vida:
  1. *Linter / Static Check en caliente:* Costo 1x (milisegundos).
  2. *Prueba Unitaria Hermética (TDD Red/Green):* Costo 2x (segundos).
  3. *Revisión por Subagentes (Council of Reviewers):* Costo 5x (1-2 minutos).
  4. *Gatekeeper / Pre-Merge:* Costo 10x.
  5. *Bug en Main / Producción:* Costo 100x+.
- **Regla de Oro:** CyberAudit y las pruebas deben actuar como barrera inmediata en el paso 3 antes de que el código llegue a los revisores humanos o a la rama principal.

### Dimensión de Pruebas (Test Sizing)
1. **Small Tests (Unitarios / Herméticos):**
   - Corren en un único proceso en memoria.
   - Cero llamadas de red reales, cero disco compartido, ejecución en < 100 ms.
   - 100% deterministas (nunca *flaky*).
2. **Medium Tests (Integración / Local):**
   - Ejecución local contra base de datos en memoria o sistema de archivos temporal aislado.
   - Verifican la interacción entre el motor de la Factory y el runner de tests del proyecto.
3. **Large Tests (End-to-End):**
   - Verifican el ciclo completo desde la creación del ticket hasta la auditoría y merge en Git.

### Filosofía de Revisión de Código (Critique)
- **Cambios Pequeños y Atómicos (Small CLs):** Modificaciones de menos de 200 líneas de código son aprobadas con el doble de rapidez y concentran un 80% menos de defectos.
- **Enfoque del Revisor:** No discutir preferencias de formato (para eso están los linters deterministas), sino auditar legibilidad, seguridad, deuda técnica oculta, contratos de concurrencia y ausencia de trampas en las pruebas.

---

## 3. Seguridad de Aplicaciones y Amenazas (Tanya Janca - Alice & Bob)

### Principios Fundamentales de AppSec
1. **Assume Breach (Asumir la Brecha):** Diseñar asumiendo que el perímetro o componentes externos ya han sido comprometidos.
2. **Defense in Depth (Defensa en Profundidad):** Múltiples capas de validación independientes. Si falla el frontend, el backend valida; si falla el backend, la base de datos o el sistema operativo aplican menor privilegio.
3. **Principle of Least Privilege (Menor Privilegio):** Procesos y subagentes deben operar con los permisos mínimos absolutos requeridos para su tarea específica (nunca root, sin acceso irrestricto a todo el disco).
4. **Attack Surface Reduction (Reducción de Superficie de Ataque):** Deshabilitar endpoints no utilizados, eliminar dependencias muertas y restringir CORS y headers de red.
5. **Never Trust, Always Verify:** Toda entrada externa (query params, body JSON, commits de git, respuestas de modelos LLM) es potencialmente hostil.

### Vectorización de Vulnerabilidades Críticas para CyberAudit
- **Inyecciones (CWE-78, CWE-89, CWE-79):**
  - **CWE-78 (OS Command Injection):** Uso inseguro de `child_process.exec` con cadenas no sanitizadas o interpoladas.
    - *Defensa Obligatoria:* Listas blancas (*Allow-lists*) de binarios permitidos, rechazo estricto de operadores shell (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`) y uso obligatorio de `spawn` con array de argumentos explícito (`shell: false`).
  - **CWE-89 (SQL Injection - SQLi):** Concatenación de consultas SQL en runtime.
    - *Defensa Obligatoria:* Consultas parametrizadas con placeholders (`$1`, `?`) o uso de ORM tipado (Prisma/TypeORM).
  - **CWE-79 (Cross-Site Scripting - XSS) & Template Injection:** Inserción de HTML/JS no escapado en el DOM o plantillas.
    - *Defensa Obligatoria:* Sanitización en contexto, uso de `textContent` / frameworks reactivos con auto-escaping y Content Security Policy (CSP).
  - **OWASP LLM01 (Prompt Injection & Jailbreaks):** Manipulación de instrucciones del sistema por entradas de usuario no neutralizadas.
- **Control de Acceso, IDOR y Autenticación (CWE-284, CWE-639):**
  - Broken Object Level Authorization: Verificar que la identidad autenticada (`userId` / `tenantId`) sea propietaria del recurso antes de mutarlo o retornarlo.
- **Gestión de Secretos y Credenciales Hardcodeadas (CWE-798):**
  - Cero credenciales en código fuente, cero tokens en logs de depuración, lectura obligatoria desde variables de entorno (`process.env`) y detección por entropía Shannon.
- **Anomalías de Concurrencia y Fallo de Persistencia Atómica (CWE-362, Invariante INV-STORAGE-006):**
  - Evitar escrituras concurrentes o truncamientos destructivos mediante el patrón atómico de archivo temporal y renombrado (`safeAtomicWrite`).
- **Bloqueo del Bucle de Eventos y Denegación de Servicio (CWE-400, Invariante INV-ASYNC-007):**
  - Prohibido el uso de I/O síncrono (`fs.readFileSync`, `execSync`) en rutas críticas de servidores Node.js/Python asíncronos.
- **Seguridad en la Cadena de Suministro (SCA / SBOM / CWE-1395):**
  - Fijación estricta de versiones semánticas (evitar comodines `*` o `^` flotantes en dependencias críticas) y generación de inventarios SBOM en formatos CycloneDX y SPDX.

---

## 4. Concurrencia, Estado y Fiabilidad en Datos (Martin Kleppmann - DDIA 2nd Ed.)

### Anomalías de Concurrencia y Carrera
1. **Lost Updates (Actualizaciones Perdidas):** Dos procesos leen el mismo archivo JSON de estado (ej. `tasks.json`) simultáneamente y sobreescriben los cambios del otro.
   - *Solución:* Serialización mediante mutex in-memory, colas de mutación FIFO o transacciones atómicas.
2. **Atomic Writes (Escrituras Atómicas en Disco):**
   - Escribir directamente en `tasks.json` con `fs.writeFile` puede corromper el archivo si el servidor se apaga o sufre un OOM a mitad del flush del buffer.
   - *Patrón Dorado:* Escribir primero en un archivo temporal (`tasks.json.tmp.<pid>`), forzar `fs.flush`/`close` y aplicar `fs.rename` atómico a nivel de sistema de archivos.
3. **Idempotencia de Eventos:**
   - Todo evento WebSocket o mensaje de webhook debe transportar un `eventId` o `timestamp` para evitar reprocesamiento duplicado ante reconexiones de red.

---

## 5. Detección de Deuda Técnica y Refactorización (Martin Fowler & Steve McConnell)

### Olores de Código (*Code Smells*) a Detectar en Revisiones:
1. **Primitive Obsession:** Usar strings planos para representar conceptos complejos (ej. pasar estados o severidades como texto arbitrario sin enum ni tipado cerrado).
2. **Long Function / God Class:** Funciones de más de 80 líneas que mezclan parseo de entrada, llamadas de red, mutación de estado y renderizado.
3. **Dead Code / Speculative Generality:** Código escrito "por si acaso" en el futuro que nunca se ejecuta y solo añade costo de lectura cognitiva.
4. **Inconsistent Error Propagation:** Atrapar errores con `catch (e) {}` vacío sin logging ni preservación de causa (`{ cause: e }`), congelando el flujo silenciosamente.
5. **Sync Blocking in Event Loop:** Usar llamadas síncronas (`fs.readFileSync`, `execSync`) en el hilo principal de Node.js, bloqueando a todos los demás clientes y WebSockets concurrentes.

---

## 6. Integración con Ecosistemas de Lenguaje y Plataformas Modernas
- **Node.js (LTS & Modern):** Manejo estricto de Streams con `pipeline`, promesas asíncronas con `fs.promises`, Node Native Test Runner (`node:test`, `node:assert`) para eliminar dependencias externas pesadas como Jest/Mocha.
- **TypeScript:** Tipado estricto (`strict: true`), Uniones Discriminadas para estados finitos de agentes, Tipos de Marca (*Branded Types*) para evitar mezclar IDs de proyectos y tareas.
- **Tailwind CSS:** Diseño utilitario basado en tokens de diseño consistentes, evitando estilos inline arbitrarios que fragmenten la interfaz.
- **Python (CyberAudit):** Tipado estático con `mypy`, análisis AST hermético sin ejecución dinámica de código inseguro, y generación estructurada de reportes JSON compatibles con SARIF.
