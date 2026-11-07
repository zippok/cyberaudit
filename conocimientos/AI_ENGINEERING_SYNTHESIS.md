# 📘 Síntesis de Conocimiento: AI Engineering (Chip Huyen, O'Reilly 2025)
### Aplicación Práctica a la AI Software Factory Studio

Este documento recopila las directrices, fórmulas, arquitecturas y lecciones maestras del libro **"AI Engineering: Building Applications with Foundation Models" (Chip Huyen, O'Reilly Media, 2025)**, correlacionadas directamente con la arquitectura de nuestra Software Factory.

---

## 1. Arquitectura de Sistemas de IA (Capítulo 10)

Chip Huyen establece la arquitectura de 5 pasos para llevar aplicaciones de modelos fundacionales a producción:

```
[Usuario / Trigger]
        │
        ▼
[1. Context Enhancement] ──► RAG, Brain (.factory/brain), File Scanner
        │
        ▼
[2. Input Guardrails]    ──► Detección de inyecciones, sanitización de PII, validación de schemas
        │
        ▼
[3. Model Router/Gateway]──► Enrutamiento dinámico (Local LM Studio / Cloud), fallback ante fallos
        │
        ▼
[4. Inference & Caches]  ──► Prompt caching, KV cache tuning, temperature adaptativa
        │
        ▼
[5. Agent Patterns]      ──► Desacoplamiento Planificación ➔ Ejecución ➔ Reflexión ➔ Gatekeeper
        │
        ▼
[Output Guardrails]      ──► Exact Evaluation (Tests reales), CyberAudit estático, Auto-Merge
```

### Lecciones para Nuestra Factory:
- **Desacoplar Planificación de Ejecución:** El Spec Writer (Paso 2) genera el plan. El Builder (Paso 3) lo ejecuta. El Consejo de Revisores (Paso 4) y Approver (Paso 5) reflexionan.
- **Acciones de Escritura Riesgosas:** *"Just as you shouldn't give an intern the authority to delete your production database, risky write actions require guardrails and human oversight."* Nuestro Gatekeeper (Paso 6) implementa esta regla dorada mediante Hard Block Rules.

---

## 2. Inferencia y Optimización de Hardware (Capítulo 9)

### A. Matemática de Memoria y KV Cache:
Para un modelo de $N$ parámetros con precisión de $P$ bytes por parámetro:
$$\text{Memoria Pesos} \approx N \times P$$
Para `Qwen 27B` en cuantización 3-bit (`Q3_K_M`):
$$\text{Memoria Pesos} \approx 27 \times 0.4 \approx 10.8 \text{ GB a } 13.6 \text{ GB}$$

**El KV Cache de la Inferencia Multitarea:**
Por cada slot paralelo con contexto $L$ y $D$ dimensiones:
$$\text{Memoria KV Cache} = 2 \times \text{layers} \times \text{heads} \times \text{head\_dim} \times L \times \text{slots} \times \text{precision}$$
- **Descubrimiento:** Con 4 slots paralelos y contexto 8192, el KV Cache consume ~2.5 a 3.5 GB adicionales de memoria física.
- **Regla:** En una máquina con 4 GB VRAM (RTX 3050) y 24 GB RAM, la GPU debe alojar ~20-24 capas (3.2 GB) y la RAM aloja las capas restantes más el KV Cache.

### B. Decodificación Especulativa (Speculative Decoding & MTP):
- La decodificación especulativa utiliza un modelo borrador (*draft model*) para predecir $K$ tokens que el modelo principal verifica en paralelo.
- **Tasa de Aceptación:** Si los tokens rechazados superan a los aceptados, la decodificación especulativa es **contraproducente** y degrada la latencia y la coherencia del muestreo.
- **Descubrimiento:** En la captura del usuario, `rejected_draft_tokens: 2387` vs `accepted: 1` (99.96% de rechazo) demostró que el draft head MTP estaba desalineado en LM Studio, arrojando alucinaciones multilingües. **Regla: Desactivar speculative drafting si la tasa de aceptación es < 60%.**

---

## 3. Estrategias de Muestreo y Razonamiento (Capítulo 2 y 5)

### A. Test-Time Compute vs Token Budgeting:
- Modelos con razonamiento interno (`<think>`) consumen tokens en pensar antes de emitir respuesta.
- Si `max_tokens` es insuficiente (ej. 800 tokens), el modelo agota la cuota durante el `<think>` y se corta (`finish_reason: length`) sin generar contenido (`content: ""`).
- **Regla:** Siempre separar el presupuesto de razonamiento (ej. 1,000 - 1,500 tokens) del presupuesto de código emitido (ej. 2,000 - 2,500 tokens).

### B. Temperatura y Colapso de Muestreo:
- Temperatura 0.0 o 0.1 en modelos MoE cuantizados en local frecuentemente causa bucles de repetición infinita o congelamiento de tokens.
- **Regla:** Para tareas de código con modelos Qwen/DeepSeek locales, fijar `temperature` entre **0.5 y 0.6** con `top_p: 0.95`.

---

## 4. Evaluación de Agentes y Calidad (Capítulos 3, 4 y 6)

### Exact Evaluation vs AI-as-a-Judge:
1. **Exact Evaluation (Funcional):**
   - La prueba reina en ingeniería de software es la ejecución real de tests: ¿Pasan los tests en el runner nativo (`npm test`)?
   - Si los tests fallan, ninguna opinión del LLM tiene validez.
2. **AI as a Judge (Cualitativo):**
   - Útil para aspectos que los tests unitarios no pueden medir directamente: mantenibilidad, arquitectura, UX, accesibilidad y diseño visual.
   - **Sesgo de AI as a Judge:** Tiende a calificar alto si no tiene datos objetivos.
   - **Nuestra Solución:** Grounding con CyberAudit Suite. Inyectar datos estáticos reales (CWEs, bloqueos de event loop) neutraliza el sesgo de benevolencia del LLM.

---

## 5. Próximas Optimizaciones para Nuestra Software Factory

1. **Context Efficiency (Poda Semántica de Archivos):** En lugar de volcar todo el árbol del proyecto en el prompt del Builder, inyectar solo los archivos importados/relevantes (filtro de dependencia estática).
2. **Gramáticas Estructuradas (Constrained Decoding):** Adoptar gramáticas GBNF o JSON Schemas en llamadas a LM Studio para garantizar 100% validez sintáctica sin depender de regex.
3. **Observabilidad por Token:** Registrar TTFT, TPOT y consumo exacto de tokens por cada uno de los 6 pasos del pipeline.
4. **Router con Fallback Gradual:** Si el modelo local devuelve ECONNRESET o OOM, degradar automáticamente a un modelo cloud o de menor contexto sin romper la tarea.
