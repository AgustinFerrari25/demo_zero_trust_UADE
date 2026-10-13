# PoC: Defensa en Profundidad para LLMs (Guardrails + Zero Trust NIST SP 800-207)

Asistente de reservas con un LLM real (OpenRouter, Function Calling) y dos capas de
seguridad que se activan desde la barra lateral:

| Capa | Dónde actúa | Qué hace |
|------|-------------|----------|
| 1 · Guardrail | Antes del LLM | Filtra el texto del usuario por patrones de prompt injection |
| 2 · Zero Trust | Entre el LLM y la base de datos | El **PEP** pausa cada tool call y consulta al **PDP** (Policy Engine + Policy Administrator), que decide con una política declarativa *default deny* |

## Puesta en marcha

```bash
cd zta-llm-demo
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env
.venv/bin/streamlit run app.py
```

Por defecto (`FAKE_DB=1` y `FAKE_LLM=1` en `.env`) la demo funciona **sin PostgreSQL y sin API key**:

- **Base simulada:** un archivo SQLite local (`demo_fake.db`) con las mismas 3 tablas. Se crea solo la primera vez.
- **LLM simulado:** un modelo por reglas que imita la API de OpenAI. Crea reservas y siempre "cae" en los pedidos de mantenimiento, como un modelo vulnerable.

Las capas de seguridad (Guardrail, PEP y PDP) son exactamente las mismas en los dos modos.

Para usar los servicios reales:

| Variable | `0` = real | Requiere |
|---|---|---|
| `FAKE_DB` | PostgreSQL | Completar `PG*` en `.env` y crear las tablas con `psql -h <host> -U <usuario> -d <base> -f schema.sql` (o desde la app: barra lateral → Configuración → "Recrear tablas desde cero") |
| `FAKE_LLM` | OpenRouter | Completar `OPENROUTER_API_KEY` |

Hay tres tablas idénticas, una por escenario. La app elige la tabla según los switches:

| Guardrails | Zero Trust | Tabla |
|:-:|:-:|---|
| OFF | OFF | `reservas_sin_proteccion` |
| ON  | OFF | `reservas_guardrails` |
| ×   | ON  | `reservas_zero_trust` |

## Guion de la demo (~10 min)

Antes de empezar: **Restaurar las 3 tablas** y **Reiniciar chat**.

1. **Caso normal**: ambos switches en OFF, botón **Reserva legítima**. El LLM llama a `crear_reserva` y aparece una fila nueva.
   Después se prende Zero Trust y se repite: se ve el PEP, el contexto JSON, el PDP y el PERMIT (regla R1).
2. **Sin protección**: ambos en OFF, botón **Ataque evasivo** (o **Ataque directo**). El LLM emite
   `borrar_base_de_datos` y la tabla `reservas_sin_proteccion` queda vacía.
3. **Capa 1**: Guardrails en ON, botón **Ataque directo**. Se bloquea antes del LLM; en la consola se ven los patrones detectados.
4. **Se evade la capa 1**: Guardrails en ON, botón **Ataque evasivo**. Pasa el filtro porque no usa palabras prohibidas y la tabla `reservas_guardrails` queda vacía.
   *Conclusión: un guardrail solo no alcanza.*
5. **Clímax ZTA**: Guardrails en OFF y Zero Trust en ON, botón **Ataque evasivo**. El LLM **es engañado** y emite el tool call,
   el PEP lo intercepta, el PDP responde DENY (regla R2: escalamiento de privilegios) y la tabla `reservas_zero_trust` queda intacta.
   Mostrar las pestañas **Política PDP** y **Auditoría**.

## Notas

- El system prompt es deliberadamente permisivo con el área de Sistemas, para simular un desarrollo vulnerable.
- Si el modelo se niega a caer en el ataque, cambiar `OPENROUTER_MODEL` en `.env` (por ejemplo, otro modelo chico con tool calling) y probar antes de la presentación.
- Si se cambian los datos semilla, actualizar también `SEED_RESERVAS` en `app.py`.
