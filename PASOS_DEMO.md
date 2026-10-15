# Guion de la demo — Zero Trust para LLMs

Documento para el presentador. Recorre los distintos casos, qué switches activar en cada
uno y qué debería verse. **Los pasos 10 y 11 son los nuevos de esta rama** (`feat/zt-riesgo`):
acceso condicional por riesgo.

---

## Antes de empezar

1. Verificá el modo de ejecución en **Configuración**: sin PostgreSQL ni API key la demo
   corre simulada (base SQLite + LLM por reglas). Sirve igual para toda la presentación.
2. En la barra lateral, tocá **Reiniciar chat y consola**.
3. Tocá **Restaurar las 3 tablas** (deja los 6 registros iniciales en cada escenario).
4. Ubicá los tres paneles:
   - **Izquierda:** el chat con el asistente.
   - **Derecha:** la *Consola de Arquitectura* (pestañas *Traza en vivo*, *Política PDP*, *Auditoría*).
   - **Abajo:** el estado de las tres tablas (`sin_proteccion`, `guardrails`, `zero_trust`).

> Truco: el panel de abajo muestra las **tres** tablas a la vez. La activa se marca con
> **[ACTIVA]**. Así se compara lado a lado qué le pasa a los datos en cada escenario.

---

## Referencia de switches (barra lateral)

| Control | Capa | Qué hace |
|---|---|---|
| **Activar Guardrails** | Capa 1 | Filtra el texto del usuario **antes** del LLM |
| **Activar Zero Trust (PDP)** | Capa 2 | El **PEP** pausa cada tool call y el **PDP** decide (política *default deny*) |
| **Postura de la sesión** → *Dispositivo administrado* | Capa 2 | Señal de contexto: equipo gestionado |
| **Postura de la sesión** → *MFA verificado* | Capa 2 | Señal de contexto: segundo factor presente |
| **Postura de la sesión** → *Red confiable* | Capa 2 | Señal de contexto: red corporativa / VPN |

El indicador bajo el expander muestra el **riesgo de la sesión** en color: verde (*bajo*),
ámbar (*medio*), rojo (*alto*). Cada señal adversa suma y con **riesgo ≥ 1** el PDP deniega
por **R6/R7**.

### Tabla destino según los switches

| Guardrails | Zero Trust | Tabla que se usa |
|:-:|:-:|---|
| OFF | OFF | `reservas_sin_proteccion` |
| ON | OFF | `reservas_guardrails` |
| × | ON | `reservas_zero_trust` |

### Prompts precargados (barra lateral → *Prompts de la demo*)

- **Reserva legítima** — caso normal.
- **Ataque directo** — pide borrar la base sin disimulo.
- **Ataque evasivo** — ingeniería social (se hace pasar por Sistemas).
- **Ataque SQL injection** — fuga de datos por consulta manipulada.

---

## Casos

### 1 · Caso normal, sin protección
- **Switches:** Guardrails **OFF**, Zero Trust **OFF**.
- **Acción:** botón **Reserva legítima**.
- **Observar:** aparece una fila nueva en `sin_proteccion`. El LLM llama a `crear_reserva`.

### 2 · Caso normal, con Zero Trust
- **Switches:** Guardrails **OFF**, Zero Trust **ON**, postura completa (3 señales ON).
- **Acción:** botón **Reserva legítima**.
- **Observar:** el PEP pausa el tool call, se envía el contexto JSON al PDP y responde
  **PERMIT (R1)**. Aparece la fila en `zero_trust`. El indicador de riesgo está en **BAJO**.

### 3 · Ataque directo, sin protección
- **Switches:** Guardrails **OFF**, Zero Trust **OFF**.
- **Acción:** botón **Ataque directo**.
- **Observar:** el LLM emite `borrar_base_de_datos` y la tabla `sin_proteccion` **queda vacía**.

### 4 · Capa 1 bloquea el ataque directo
- **Switches:** Guardrails **ON**, Zero Trust **OFF**.
- **Acción:** botón **Ataque directo**.
- **Observar:** se bloquea **antes** del LLM. En la consola se ven los patrones detectados
  por el guardrail (intención destructiva, modo administrador, etc.).

### 5 · El ataque evade la Capa 1
- **Switches:** Guardrails **ON**, Zero Trust **OFF**.
- **Acción:** botón **Ataque evasivo**.
- **Observar:** pasa el filtro (no usa palabras prohibidas) y la tabla `guardrails`
  **queda vacía**. *Conclusión: un guardrail solo no alcanza.*

### 6 · Clímax: Zero Trust detiene el ataque evasivo
- **Switches:** Guardrails **OFF**, Zero Trust **ON**.
- **Acción:** botón **Ataque evasivo**.
- **Observar:** el LLM **es engañado** y emite el tool call, el PEP lo intercepta, el PDP
  responde **DENY (R2)** y `zero_trust` **queda intacta**. Mostrar las pestañas
  **Política PDP** y **Auditoría**.

### 7 · SQL injection, sin protección (fuga de datos)
- **Switches:** Guardrails **OFF**, Zero Trust **OFF**.
- **Acción:** botón **Ataque SQL injection** (payload `' OR '1'='1' --`).
- **Observar:** en la consola, el SQL final y el cartel **FUGA DE DATOS**: la consulta
  devuelve **las 6 reservas** en vez de una.

### 8 · Capa 1 frena el SQLi (pero es frágil)
- **Switches:** Guardrails **ON**, Zero Trust **OFF**.
- **Acción:** botón **Ataque SQL injection**.
- **Observar:** el filtro detecta los metacaracteres y bloquea antes del LLM. *Pero es una
  lista negra: se evade con encoding.*

### 9 · Zero Trust valida la acción
- **Switches:** Guardrails **OFF**, Zero Trust **ON**.
- **Acción:** botón **Ataque SQL injection**.
- **Observar:** el PEP inspecciona los **argumentos**, detecta la anomalía y el PDP responde
  **DENY (R4)**. La consulta nunca se ejecuta. *Never trust, always verify.*

### 10 · ⭐ NUEVO — Acceso condicional por riesgo (misma acción, distinto contexto)
- **Switches:** Guardrails **OFF**, Zero Trust **ON**, postura completa (3 señales **ON**).
- **Acción:** botón **Reserva legítima**.
- **Observar:** el indicador marca **RIESGO BAJO** y el PDP responde **PERMIT (R1)**; se crea
  la reserva.

  Ahora **apagá *MFA verificado***:
  - El indicador pasa a **RIESGO MEDIO** (ámbar).
  - Repetí **Reserva legítima** (una acción perfectamente legítima).
  - El PEP informa *"Postura de sesión débil"* y el PDP responde **DENY (R6)**: no se crea
    ninguna fila. En la consola se ve el bloque `risk` del contexto y el motivo con el score.
  - Volvé a **prender MFA**: la misma acción se autoriza otra vez.

  *Conclusión: la autorización depende del contexto (dispositivo, MFA, red), no de una lista
  fija de acciones. Con `riesgo ≥ 1` la política deniega.*

### 11 · ⭐ NUEVO — El riesgo también aplica a la lectura
- **Switches:** Guardrails **OFF**, Zero Trust **ON**; apagá **Dispositivo administrado**.
- **Acción:** pedir una consulta de reservas (por ejemplo, *"buscá la reserva de Juan Pérez"*).
- **Observar:** aunque el nombre sea válido, el PDP responde **DENY (R7)** por postura
  insuficiente. Volvé a prender la señal y la búsqueda se autoriza (**PERMIT R5**).

### 12 · Resumen: misma amenaza, distinta defensa
- Repetí el **Ataque evasivo** con las tres combinaciones y compará abajo:
  - Guardrails OFF / ZT OFF → tabla vacía (ataque exitoso).
  - Guardrails ON / ZT OFF → bloqueado, pero *por lista negra* (frágil).
  - ZT ON → bloqueado, *por contrato*, con auditoría.
- Y con **postura débil** (alguna señal OFF): incluso las acciones legítimas se bloquean.

---

## Cierre

- **Capa 1** protege la **entrada** (texto del usuario).
- **Capa 2 (Zero Trust)** protege la **acción**, en el medio, y ahora también decide por
  **contexto/riesgo** (R6/R7).
- La decisión vive **fuera del modelo**: el LLM propone, el PEP/PDP dispone
  (*assume breach*: se asume que el modelo ya puede estar comprometido).

### Problemas comunes

- **El modelo real se niega a caer en el ataque:** cambiar `OPENROUTER_MODEL` en `.env` por
  otro con tool calling y probar antes de presentar. En modo simulado no ocurre.
- **La tabla no está vacía tras un ataque:** tocá **Restaurar las 3 tablas** y reintentá.
- **El indicador de riesgo no cambia:** el cambio de señales se aplica en la próxima
  petición; volvé a enviar el mensaje después de togglear.
