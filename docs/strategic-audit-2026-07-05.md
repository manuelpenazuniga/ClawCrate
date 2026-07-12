# ClawCrate — Auditoría Estratégica 2026-07-05

**Fecha del reporte:** 2026-07-05
**Branch revisado:** `issue/266-canonicalize-replica-temp-path` (working tree limpio, ramas alineadas con `main`).
**Release público más reciente:** `v0.2.0-alpha.0` (tag preparado 2026-06-20).
**Predecesores directos:**
- `docs/strategic-audit-2026-06-19.md` — corte previo (estado + riesgos de release).
- `docs/roadmap-2026-05-09.md` — 5 leap initiatives (backlog vivo).
- `docs/strategic-audit-2026-05-03.md` — landscape competitivo original.
- `clawcrate-v3.1.1.md` — spec fundacional (§4 landscape).

Este documento hace tres cosas que los cortes anteriores no hicieron juntas:

1. **Audita el avance real contra el código**, no contra el plan. (El plan de `CLAUDE.md` describe un producto de 6 semanas; el repo real es un producto de ~9 meses con Compliance Kit y MCP Firewall entregados.)
2. **Reencuadra el dolor en su máxima abstracción** para separar el mecanismo (sandbox) del producto (gobernanza de acciones de agentes).
3. **Define los diferenciales defendibles y los apostables**, con un roadmap accionable para capturar adopción.

---

## 0. TL;DR — el veredicto en cinco frases

1. **Técnicamente estamos mejor que nunca:** Compliance Kit (hash chain + verify + Ed25519 + SIEM export) y MCP Server Firewall (`clawcrate mcp wrap` + relay JSON-RPC + auto-detección + recetas) están **entregados** en `main`. Dos de las cinco leap initiatives del roadmap 05-09 están cerradas.
2. **El diferencial más valioso ya no es el sandbox:** el sandbox kernel-nativo es commodity (Codex, Cursor, Claude Code ya lo tienen internalizado). Nuestro moat real es la **capa horizontal de política + evidencia auditable + ecosistema** que ningún vendor de agente puede replicar porque es *agent-agnostic*.
3. **El gap de producto #1 es de seguridad y es corregible:** en Linux Direct Mode no bloqueamos **lectura** de secretos (Landlock solo media escritura). El titular "tu agente no puede leer tus llaves" hoy solo se sostiene en macOS o Linux+Replica. Cerrar esto (Landlock read-allowlisting) es la mejora de mayor apalancamiento.
4. **El unlock de adopción 0→1 es `clawcrate learn`:** la fricción #1 de cualquier sandbox es escribir la política. Nadie en el ecosistema deriva política automáticamente de un trace. Es la feature que convierte a ClawCrate de "para paranoicos que escriben YAML" a "para cualquiera con un agente".
5. **La ventana es corta:** cada vendor de agente está construyendo su propia frontera de ejecución. O nos volvemos la capa estándar antes de que se consolide un de-facto interno, o quedamos como un tool de nicho. Los próximos 90 días deciden la categoría.

---

## 1. Auditoría del avance (anclada en código, no en plan)

### 1.1 Qué se entregó desde el corte del 2026-06-19

| Área | Estado 2026-06-19 | Estado 2026-07-05 |
| --- | --- | --- |
| Compliance Kit (hash chain, verify, sign, SIEM) | Entregado en `main`, sin release | Publicado en `v0.2.0-alpha.0` |
| `clawcrate mcp wrap` (subcomando) | Issue #253 abierta | **Entregado** (PR #260) |
| Relay stdio JSON-RPC transparente | Issue #254 abierta | **Entregado** (PR #261) |
| Auto-detección de shape MCP | Issue #255 abierta | **Entregado** (PR #262) |
| Recetas Claude Desktop / Cursor / Continue.dev | Issues #256-#258 | **Entregadas** (docs/integrations/) |
| Demo filesystem MCP (#259) | Abierta | WIP en stash (`issue/259-mcp-filesystem-demo`) |

**Lectura:** el epic MCP Server Firewall (leap initiative #4 del roadmap 05-09) está **funcionalmente completo**. Las 5 sub-issues de código cerraron; solo falta pulir la demo #259 y — más importante — **convertir la capacidad en narrativa distribuible** (ver §6.3).

### 1.2 Métricas de código (estado real)

| Métrica | Valor | Nota |
| --- | ---: | --- |
| LOC Rust (sin `target/`) | ~15.100 | 6 crates |
| Tests (`#[test]`) | 202 | CI en Linux + macOS (matrix) |
| `crates/clawcrate-cli/src/main.rs` | **5.859 líneas** | Era 4.752 el 19-06. Sigue creciendo. |
| Suite local | Verde | fmt + clippy `-D warnings` + workspace tests + fixtures + golden |
| CI | 2 jobs × 2 OS | `Rust Checks` + `Integration + Fixtures` |
| Community profiles | 6 | `agent-inference-allowlist`, `mcp-server`, `mcp-readonly`, `npm-install-allowlist`, `pip-install-pypi-only`, catálogo |

### 1.3 Qué falta de las 5 leap initiatives

| Epic (roadmap 05-09) | Milestone | Estado 2026-07-05 |
| --- | --- | --- |
| #2 Compliance Kit | v0.2.0 | ✅ **Cerrado y publicado** |
| #4 MCP Server Firewall | v0.2.0 | ✅ **Código cerrado** (falta demo + distribución) |
| #5 GitHub Action + integraciones + VS Code | v0.3.0 (#220) | ⬜ No iniciado |
| #3 `profiles.dev` marketplace | v0.3.0 (#221) | ⬜ Semilla parcial (catálogo local, sin registro remoto) |
| #1 `clawcrate learn` auto-policy | v0.4.0 (#222) | ⬜ No iniciado |

**Diagnóstico honesto de ritmo:** el patrón repetido en todos los cortes previos (05-03, 05-09, 06-19) es **ráfaga de ejecución seguida de pausa larga**. El cuello de botella nunca fue el plan ni la capacidad técnica; es la **continuidad de ejecución**. El repo tiene valor unreleased suficiente para 2-3 anuncios públicos que no se han capitalizado.

---

## 2. El dolor, en su máxima abstracción

Pedir "seguridad para agentes" es quedarse en la superficie. Abstraigamos en cuatro niveles; cada uno reencuadra el producto.

### Nivel 0 — El incidente (lo que el usuario ve)
Un `npm install` con postinstall malicioso lee `~/.ssh/id_rsa`, `~/.aws/credentials` y los `.env`, y los exfiltra. El usuario se entera cuando llega la factura de $14.000 en GPUs. Este es el gancho del README, y es real (Cline/VS Code feb-2026, Shai-Hulud v3).

### Nivel 1 — La causa estructural (lo que de verdad falla)
Los agentes AI ejecutan comandos con la **autoridad ambiental** del humano que los lanzó: heredan *todo* el blast radius de la identidad del usuario — filesystem, variables de entorno, red, credenciales, keychain. **No existe principio de mínimo privilegio en la frontera acción-del-agente.** El agente decide qué ejecutar; el OS le concede lo mismo que al humano. La brecha no es "malware"; es que **la unidad de confianza del sistema operativo es el usuario, no la acción**.

### Nivel 2 — El cambio de época (por qué esto es nuevo ahora)
Estamos en la transición de "software que un humano escribe y revisa" a "software que un agente genera y ejecuta". El modelo de confianza de la computación asumía un **humano en el loop, accountable, determinista**. Los agentes rompen las tres asunciones:
- **No determinista:** la misma entrada produce comandos distintos.
- **Persuadible:** vulnerable a prompt injection — la lógica de negocio del agente es el input no confiable.
- **A velocidad y escala de máquina:** el humano no alcanza a revisar cada comando.

La primitiva que falta es una **frontera de capacidades alrededor de la acción del agente**: mínima autoridad, impuesta externamente (no autoimpuesta por el agente, que es persuadible), y **auditable** (porque cuando algo salga mal, alguien tendrá que probar qué tocó el agente y qué no).

### Nivel 3 — El vacío de mercado (dónde está el dinero y el moat)
Cada vendor de agente está construyendo esta frontera **internamente y de forma incompatible**: Codex trae su Seatbelt/Bubblewrap, Cursor el suyo, Claude Code su sandbox-runtime. Es el momento "cada navegador implementa su propio TLS" *antes* de que emerja una capa compartida. Tres consecuencias:
- La frontera de ejecución de agentes es **infraestructura sin dueño horizontal**.
- La política ("qué puede hacer `npm install`") se reinventa por agente y por usuario — **coste repetido, cero efecto de red**.
- La evidencia (¿qué hizo el agente?) es un log plano por vendor, **no portable, no admisible, no comparable**.

> **La tesis de ClawCrate, formulada correctamente:** no competimos por ser "un mejor sandbox que el de Codex" — el sandbox de Codex solo sirve a Codex. Competimos por ser **la frontera compartida y agent-agnostic** que (a) cualquier agente puede adoptar, (b) produce evidencia portable y tamper-evident, y (c) se gobierna con política portable (perfiles) que sobrevive a cualquier agente individual. **El sandbox es el mecanismo; el producto es la gobernanza de acciones de agentes: mínima autoridad + evidencia.**

Esta reformulación importa porque cambia el ICP, el mensaje y el moat. Si "somos un sandbox", competimos contra kernels y contra el sandbox interno de cada agente (batalla perdida: es commodity). Si "somos la capa de política + evidencia para acciones de agentes", el sandbox es solo el enforcement y el moat está arriba: **política reutilizable (learn + marketplace) + evidencia auditable (compliance kit) + neutralidad (cualquier agente)**.

---

## 3. Landscape competitivo actualizado y el lugar de OpenClaw

### 3.1 Cómo sandboxean hoy los agentes (y qué cambió)

| Actor | Mecanismo | Standalone | Audit-grade | Agent-agnostic | Política reutilizable |
| --- | --- | :-: | :-: | :-: | :-: |
| **Codex (OpenAI)** | Seatbelt / Bubblewrap+Landlock | ❌ interno | ❌ | ❌ | ❌ |
| **Cursor** | Seatbelt / Landlock | ❌ interno | ❌ | ❌ | ❌ |
| **Claude Code** | sandbox-runtime (Seatbelt/bwrap) | ❌ interno | ❌ | ❌ | ❌ |
| **NemoClaw / Membrane** | Docker (+eBPF) | ✅ | parcial | ✅ | ❌ |
| **microsandbox / microVM** | microVM (KVM) | ✅ | ❌ | ✅ | ❌ |
| **alcless (NTT)** | usuario separado + rsync | ✅ | ❌ | ✅ | ❌ |
| **sx (sandbox-shell)** | Seatbelt (macOS only) | ✅ | ❌ | ✅ | ❌ |
| **nono** | Merkle audit (closed) | ✅ | ✅ | parcial | ❌ |
| **ClawCrate** | Landlock+seccomp / Seatbelt | ✅ | **✅** | **✅** | **✅ (catálogo, → marketplace)** |

**Movimiento estratégico clave del ecosistema:** los agentes están **internalizando** el sandbox como feature propia. Esto tiene dos lecturas:
- **Amenaza:** si Anthropic/OpenAI open-sourcean su sandbox-runtime completo y "suficientemente bueno", el diferencial "sandbox nativo dual-platform" se evapora.
- **Oportunidad (más grande):** precisamente porque cada uno hace el suyo, **nadie posee la capa horizontal**. El sandbox interno de un agente no audita de forma portable, no comparte política, y no sirve a los otros agentes ni a los MCP servers ni a CI. Ese es exactamente el hueco de ClawCrate.

### 3.2 El lugar de OpenClaw — nuestra mayor superficie de distribución

OpenClaw es el agente que usamos como proxy de mercado (la distribución de OS del README — 68.5% macOS / 22.1% Linux / 9.4% WSL2 — es la de sus usuarios). Estratégicamente, OpenClaw es **tres cosas para nosotros**:

1. **El termómetro del mercado:** su base de usuarios define dónde está el volumen (macOS domina → nuestra paridad macOS/Linux es correcta, y explica por qué el gap de lectura en Linux "solo" toca a un tercio... pero es el tercio de *producción*, ver §4.1).
2. **La superficie de integración más grande:** un agente OSS con base amplia que ejecuta shell y monta MCP servers. Si ClawCrate se vuelve el *execution boundary recomendado* de OpenClaw, ganamos distribución instantánea sin construir un agente.
3. **La prueba de la tesis agent-agnostic:** hoy nos integramos con OpenClaw *igual* que con Claude Code, Cursor o Codex — con `clawcrate run -- <cmd>` y `clawcrate mcp wrap`. Que el mismo binario sirva a todos es *la demostración viva del diferencial horizontal*.

> **Apuesta concreta de distribución:** pasar de "receta en docs" a **integración de primera clase con OpenClaw** (un hook/plugin oficial que enrute la ejecución de shell y el arranque de MCP servers por ClawCrate por defecto). Es el canal de adopción de mayor ROI porque hereda una base instalada en vez de construirla.

---

## 4. Auditoría de seguridad — hallazgos accionables (2026-07-05)

Fortalezas confirmadas (no repito el detalle de 06-19): macOS con enforcement real Seatbelt; env scrub cubre `AWS_*`/tokens/keys/`SSH_AUTH_SOCK`/`DATABASE_URL`; `CLAWCRATE_AUDIT_*` se elimina siempre del child; hash chain + verify + Ed25519 + SIEM; API local con bearer token de comparación constante.

Los hallazgos siguientes están **verificados contra el código en este corte**, ordenados por apalancamiento.

### 4.1 🔴 P0 — Linux Direct Mode no aísla LECTURA (asimetría estructural con macOS)

**Evidencia (código):** `crates/clawcrate-sandbox/src/linux.rs`.
- `landlock_write_access_mask_for_abi()` construye la máscara **solo** con `LANDLOCK_ACCESS_FS_BASE_WRITE` (+ `REFER`/`TRUNCATE` según ABI).
- `open_linux_landlock_write_path_fds()` itera **solo** `prepared.fs_write`.
- No existe `handled_access_fs` para `ACCESS_FS_READ_FILE`/`READ_DIR`, ni reglas derivadas de `fs_read`.

**Consecuencia:** Landlock nunca media lecturas. En Linux Direct Mode un proceso sandboxeado **puede leer `~/.ssh/id_rsa`, `~/.aws/credentials`, cualquier `.env` fuera del workspace**. El landmark test del spec ("`cat ~/.ssh/id_rsa` → EACCES") **solo pasa en macOS o en Linux+Replica**. Está documentado con honestidad en README/CHANGELOG — no es engaño — pero es un **gap de producto**, no solo de docs: el 22% Linux es infraestructura de *producción*, donde los secretos importan más.

**Recomendación (alto apalancamiento):** implementar Landlock **read-allowlisting**. Declarar `ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR` en `handled_access_fs` y conceder lectura solo a: (a) los anchors de `fs_read`, (b) los paths de sistema/toolchain necesarios (`/usr`, `/lib*`, `/etc/ssl`, el intérprete). El reto real es enumerar el read-set sin romper el proceso — **exactamente el problema que resuelve `clawcrate learn`** (§6.4). Sinergia: `learn` deja de ser "nice to have" y se vuelve *habilitador de seguridad* en Linux.

**Mitigación inmediata (0 código):** hacer que `install` y perfiles de riesgo defaulteen a Replica también en Linux (ya lo hacen para `install`), y que el `plan`/`doctor` **adviertan explícitamente** cuando se corre Direct en Linux con perfiles que prometen read-isolation.

### 4.2 🟠 P1 — seccomp es denylist, no allowlist (viola "deny by default")

**Evidencia:** `build_linux_seccomp_rules()` + `SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(EPERM), arch)`. La acción por defecto (mismatch) es **`Allow`**; solo se bloquea una lista fija de syscalls peligrosas (`ptrace`, `mount`, `kexec_load`, etc.).

**Consecuencia:** cualquier syscall nueva/obscura no listada **pasa**. El spec (`CLAUDE.md`) especificaba un **allowlist** ("Default profile allows: read, write, open, ..."). La implementación actual es un **denylist**, más débil y más frágil ante kernels nuevos.

**Recomendación:** migrar a allowlist con `mismatch_action = Errno(EPERM)` y un set explícito de syscalls permitidas por perfil (con `CompatLevel`/probing para no romper libc modernas). Es más trabajo de compatibilidad, pero es la postura que promete la filosofía del proyecto. Alternativa mínima: documentar explícitamente que la capa syscall es denylist best-effort y ampliar la denylist con las clases OWASP Agentic conocidas.

### 4.3 🟠 P1 — Artifacts sin permisos restrictivos

`ArtifactWriter` usa `create_dir_all` / `OpenOptions` sin `0700`/`0600`. La confidencialidad de `audit.ndjson` (evidencia de compliance) **depende del umask del operador**. Para un producto que se vende como "audit-grade / EU AI Act Article 12", esto es incoherente. **Recomendación:** forzar `0700` en `~/.clawcrate` y runs, `0600` en artefactos, en creación (no post-hoc).

### 4.4 🟡 P2 — `api --bind` permite exposición no-loopback

Default `127.0.0.1` (correcto). Pero `--bind 0.0.0.0` expone el servicio con solo bearer token. **Recomendación:** rechazar bind no-loopback salvo `--allow-remote-bind` explícito + warning fuerte.

### 4.5 🟡 P2 — `network: filtered` es proxy-mediado, best-effort

El egress proxy tiene enforcement SNI para CONNECT y cola acotada, pero depende de que la herramienta respete `HTTP(S)_PROXY/ALL_PROXY`. Un binario que abre sockets directos evade el filtro de dominio. Ya está documentado como caveat; **la mejora estructural** es enforcement a nivel red (loopback-only egress + bloqueo de conexión directa por backend, o intercepción DNS) — es trabajo de v1.0 (cierra el threat model residual). No sobrevender como "domain firewall" hasta entonces.

---

## 5. Auditoría de escalabilidad — deuda que frena la próxima fase

| # | Hallazgo | Evidencia | Impacto | Recomendación |
| --- | --- | --- | --- | --- |
| 5.1 | **Monolito `main.rs`** | 5.859 líneas, 188 items top-level, 1 solo `mod tests`; concentra CLI+API+bridge+replica+verify+export+mcp+run | Cada feature nueva (learn, action) aumenta el riesgo de regresión y frena contribuciones externas | **Extraer módulos** (`run`, `api`, `replica`, `mcp`, `audit_export`, `verify`) *antes* de v0.3.0. Es prerequisito de "adopción contributor". |
| 5.2 | **Replica = copia recursiva completa** | Replica materializa copia filtrada íntegra | Lento en monorepos y en MCP filesystem servers (que apuntan a `$HOME`) | CoW/reflink (APFS `clonefile`, Linux `FICLONE`) + hardlinks; o **replica por allowlist** (copiar solo lo declarado). Crítico para que MCP wrap sea usable en árboles grandes. |
| 5.3 | **fs-diff hashea contenido completo** | snapshot pre/post con SHA-256 de cada archivo en roots escribibles | Caro en árboles grandes | Modo **metadata-first** (size+mtime), hash bajo demanda; mantener modo audit-grade opt-in. |
| 5.4 | **API `tiny_http` + subprocess por request** | workers fijos, ejecuta el binario por cada plan/run | Suficiente local; no multi-cliente | Documentar límites; no migrar a Tokio ahora. Cola acotada ya existe. |
| 5.5 | **Egress proxy thread-por-conexión (cap 64)** | `egress_proxy.rs` | Dev local OK | No venderlo como proxy de throughput; mantener cota. |

**Prioridad de escalabilidad:** 5.1 (refactor monolito) es *bloqueante blando* para todo lo demás — habilita contribuciones y reduce el riesgo de las features grandes (learn, action). 5.2 (replica CoW) es lo que hace **usable** el diferencial MCP en el caso real (filesystem server sobre `$HOME`).

---

## 6. Diferenciales: los que tenemos y los que debemos construir

### 6.1 Diferenciales defendibles HOY (código en `main`)

1. **Único sandbox standalone dual-platform nativo, sin Docker, en Rust** — Landlock+seccomp / Seatbelt, single binary, sin root. (El resto del mercado: o es interno de un agente, o requiere Docker, o es macOS-only.)
2. **Audit-grade por defecto, open-source MIT** — hash chain SHA-256 + canonical JSON (RFC 8785) + `verify` offline + firma Ed25519 + export SIEM (cef/syslog/elastic/json). **Iguala a `nono` pero abierto; supera a los sandbox-runtime de los agentes, que emiten logs planos.** Este es hoy nuestro diferencial *enterprise* más fuerte.
3. **MCP Server Firewall** — `clawcrate mcp wrap` sandboxea cualquier MCP server stdio **sin que el cliente (Claude Desktop/Cursor/Continue.dev) note la diferencia** (relay JSON-RPC transparente). Nadie más sandboxea MCP. Es el diferencial más *timely*.
4. **Agent-agnostic real** — el mismo binario sirve a OpenClaw, Claude Code, Codex, Cursor, Gemini CLI, CI. La neutralidad es el diferencial que ningún vendor de agente puede copiar sin dejar de ser vendor de agente.
5. **Compliance narrativa concreta** — mapeo EU AI Act Art. 12/19/26 + alineación IETF draft-sharif. Convierte "seguridad" en "evidencia regulatoria", que es un *driver de compra*, no un nice-to-have.

### 6.2 Diferenciales a construir (apuestas, ordenadas por ROI de adopción)

Cada uno resuelve un dolor que ningún competidor cubre al 2026-07. La secuencia importa: **wedge → unlock → moat**.

### 6.3 🥇 Wedge: MCP Firewall como narrativa distribuible (v0.2.0 → ahora)
El código existe; falta el **producto de adopción**. La capacidad "sandbox any MCP server transparently" es la más viral y timely (Shai-Hulud v3 ataca configs MCP *hoy*), pero solo convierte si es **demoable y de instalación en una línea**.
- Cerrar la demo #259 (`@modelcontextprotocol/server-filesystem` sandboxeado leyendo `$HOME` → intento de exfil → blocked, con audit chain verificable).
- **Instalador de config:** `clawcrate mcp install --client cursor --profile mcp-readonly -- <server>` que reescribe el `mcp.json` del cliente por el usuario. Pasar de "copia este JSON" a "un comando".
- Video 60s + blog "ClawCrate stops Shai-Hulud v3". Este es el anuncio que capitaliza el trabajo ya hecho.

### 6.4 🥈 Unlock: `clawcrate learn` — auto-política desde trace (el 0→1 de adopción)
**El dolor:** la fricción #1 de todo sandbox es *escribir la política*. Hoy el usuario adivina, lee YAML, itera contra falsos positivos. **La idea:** ejecutar el comando bajo tracing (Linux: `ptrace`/seccomp-unotify/eBPF; macOS: best-effort/caveat) y **sintetizar el perfil tightest-fit**. Sinergia doble:
- Es el *habilitador* del fix de seguridad §4.1 (para conceder read-allowlist en Linux hay que *conocer* el read-set — `learn` lo descubre).
- Es la feature que un evaluador prueba en 5 minutos y queda enganchado. **Nadie en el ecosistema la tiene.** Convierte el ICP de "dev paranoico" a "cualquiera con un agente".

### 6.5 🥉 Moat: `profiles.dev` — registro firmado de política reutilizable (efecto de red)
**El dolor:** cada usuario reinventa el perfil de `npm install`, `pytest`, `cargo build`. La política es hoy un **coste repetido sin efecto de red**. **La idea:** registro público de perfiles community **firmados** (MVP: SHA256 + GitHub raw; luego sigstore + transparency log). `clawcrate profiles search/install`, y eventualmente resolución automática (`clawcrate run -- pytest` busca el perfil firmado más reciente).
- Convierte la política de coste individual en **activo compartido**. Cada perfil nuevo beneficia a todos → *network effect*.
- Es el moat de largo plazo que **ningún vendor de agente puede replicar**, porque un registro agent-agnostic de política es incompatible con ser dueño de un agente.

### 6.6 Diferencial-paraguas (posicionamiento): "Policy + Evidence for Agent Actions"
Los cuatro diferenciales anteriores no son features sueltas; son las **tres capas de una única categoría**:
- **Política de mínima autoridad** (perfiles + `learn` + marketplace) — *qué puede hacer la acción*.
- **Enforcement kernel-nativo** (Landlock/seccomp/Seatbelt) — *que no pueda hacer más*.
- **Evidencia tamper-evident** (compliance kit) — *prueba de qué hizo*.

Dejar de vendernos como "un sandbox" y vendernos como **"la capa de gobernanza para acciones de agentes: mínima autoridad + evidencia, para cualquier agente"**. El sandbox es el cómo; la gobernanza auditable es el qué.

---

## 7. Roadmap detallado (2026-07-05 → 2027 Q1)

Reordena el roadmap 05-09 a la luz de lo entregado, con foco en **capitalizar lo hecho** antes de construir lo nuevo. Fechas de referencia: hoy 2026-07-05; EU AI Act plena aplicación **2026-08-02** (a 28 días).

### Fase A — Capitalizar (2026-07-05 → 2026-08-02) · "convertir código en adopción"
Objetivo: no dejar valor unreleased sin narrativa antes de la ventana AI Act.

| # | Entregable | Diferencial | Esfuerzo |
| --- | --- | --- | --- |
| A1 | **Publicar `v0.2.0-alpha.0`** (si no está pusheado) + release notes | Compliance + MCP | S |
| A2 | **Cerrar demo MCP #259** (exfil → blocked, audit verificable) | 6.3 wedge | S |
| A3 | **`clawcrate mcp install --client <cursor\|claude\|continue>`** (reescribe `mcp.json`) | 6.3 wedge | M |
| A4 | **Blog + video 60s:** "AI Act Art.12 en un comando" + "ClawCrate stops Shai-Hulud v3" | 6.1/6.3 | S |
| A5 | **Hardening pre-narrativa:** artifacts `0600/0700` (§4.3), warning bind no-loopback (§4.4), warning Direct-en-Linux (§4.1 mitigación) | Seguridad | S |
| A6 | Publicar **compliance statement** EU AI Act Art.12 | 6.1 | S |

**Marketing window 2026-08-02:** HN / Lobsters / r/rust; CFP (RustConf, AI Eng Summit). Meta: convertir 50 días de trabajo unreleased en tracción.

### Fase B — Cerrar el gap de seguridad + habilitar contribución (2026-08 → 2026-09)
Objetivo: eliminar la asimetría Linux y preparar el código para features grandes.

| # | Entregable | Referencia | Esfuerzo |
| --- | --- | --- | --- |
| B1 | **Landlock read-allowlisting** (paridad de read-isolation Linux/macOS) | §4.1 | L |
| B2 | **Refactor `main.rs` → módulos** (`run`/`api`/`replica`/`mcp`/`audit_export`/`verify`) | §5.1 | M |
| B3 | **Replica CoW/reflink + hardlinks** (APFS `clonefile` / Linux `FICLONE`) | §5.2 | M |
| B4 | seccomp allowlist opt-in (o denylist ampliada + doc honesta) | §4.2 | M |
| B5 | **Integración de primera clase con OpenClaw** (hook/plugin execution boundary) | §3.2 | M |

### Fase C — El unlock de adopción (2026-09 → 2026-11) · `clawcrate learn`
Objetivo: la feature que baja la fricción de política a cero. Linux first-class, macOS con caveat honesto.

| # | Entregable | Esfuerzo |
| --- | --- | --- |
| C1 | Trace harness Linux (`ptrace`/seccomp-unotify/eBPF): captura reads/writes/net/env/procs | L |
| C2 | Profile synthesizer (trace → YAML tightest-fit) + algoritmo de cobertura mínima de read-paths | M |
| C3 | `clawcrate learn` subcomando + "add to community catalog?" | S |
| C4 | Integración con B1: `learn` genera el read-allowlist Linux | S |
| C5 | macOS trace harness best-effort (DTrace/ESF) + doc de caveats SIP | M |

### Fase D — El moat de red (2026-11 → 2027 Q1) · `profiles.dev` + distribución
| # | Entregable | Esfuerzo |
| --- | --- | --- |
| D1 | `clawcrate profiles fetch/search/install` (MVP: GitHub raw + SHA256) | M |
| D2 | Repo `clawcrate/profiles` + seed top-50 (cargo, pytest, npm-*, go build) | M |
| D3 | Resolución automática de perfil por comando | M |
| D4 | GitHub Action `clawcrate/action@v1` (upload-audit, fail-on-tampering) | S |
| D5 | VS Code extension MVP (run-under-clawcrate + audit panel) | M |
| D6 | Homebrew tap + `cargo install` + npm wrapper | S |
| D7 | sigstore signing + transparency log (moat completo) | L |

### Fase E — v1.0 surface freeze (2027 Q1)
Enforcement de red estructural (loopback-only egress / DNS interception, §4.5) · `clawcrate replay` (reproducibilidad) · decisión Windows (post-señal) · certificaciones (SOC2 Type 1, statement AI Act) · plugin system.

### Ruta crítica visual
```
A (capitalizar) ──► B (cerrar gap seguridad + refactor) ──► C (learn) ──► D (marketplace + distribución) ──► E (v1.0)
   0 código nuevo        habilita todo lo demás           unlock 0→1        moat de red              freeze
   ventana AI Act        paridad Linux/macOS              adopción masiva   efecto de red
```

---

## 8. Riesgos a monitorear (actualizado)

| Riesgo | Prob | Impacto | Mitigación |
| --- | :-: | :-: | --- |
| **Pausa de ejecución post-v0.2.0** (patrón histórico) | **Alta** | **Alta** | Fase A es 0 código nuevo — es pura capitalización. No hay excusa técnica para no ejecutarla. |
| Anthropic/OpenAI open-sourcean sandbox-runtime completo | Media | Alta | Diferenciar por audit (6.1) + learn (6.4) + marketplace (6.5) + neutralidad. El sandbox es commodity; el moat está arriba. |
| Gap read-isolation Linux se explota/publica antes de B1 | Media | Alta | Mitigación 0-código en A5 (warnings); B1 prioritario. No sobreprometer en marketing. |
| Replica lenta hace MCP wrap inusable en árboles grandes | Media | Media | B3 (CoW) antes de empujar MCP como caso principal. |
| MCP estándar evoluciona | Media | Baja | Relay es delgado; catálogo community absorbe cambios. |
| Apple endurece/retira `sandbox-exec` | Media | Alta | Fallback estilo alcless (usuario separado) documentado; ESF research en E. |

---

## 9. Dirección clara — las tres decisiones que importan

1. **Ejecuta la Fase A ya.** Hay ~50 días de trabajo entregado sin narrativa pública. El acto de mayor ROI no es código: es **publicar la demo MCP, el instalador de config y los dos blogs** dentro de la ventana AI Act. Sin esto, el mejor Compliance Kit del ecosistema es invisible.
2. **Cierra el gap de seguridad #1 (Landlock read) como prioridad de producto, no de docs.** Es lo que hace verdadero el titular en el 100% de las plataformas, y `learn` (Fase C) lo habilita de forma elegante. Hasta B1, sé honesto en marketing: read-isolation es macOS + Linux/Replica.
3. **Posiciónate como capa de gobernanza, no como sandbox.** El sandbox es commodity y cada agente hace el suyo. El moat defendible es la tríada **política reutilizable + enforcement + evidencia auditable, agent-agnostic**. Los tres diferenciales a construir (learn, marketplace, MCP distribución) son las tres capas de esa categoría — y ningún vendor de agente puede seguirte ahí sin dejar de ser vendor de agente.

**Veredicto:** ClawCrate tiene el mejor estado técnico de su historia y un diferencial de compliance + MCP que nadie más combina en open source. El riesgo no es técnico ni de mercado — es de **continuidad de ejecución y de capitalización**. Los próximos 28 días (capitalizar) y los siguientes 90 (cerrar el gap + `learn`) deciden si ClawCrate es la capa estándar de gobernanza de acciones de agentes o un tool de nicho que llegó primero y no cobró la ventaja.

---

*Auditoría escrita 2026-07-05. Anclada en el código del branch `issue/266-canonicalize-replica-temp-path`. Revisión recomendada al cierre de la Fase A (post-ventana AI Act) o a los 30 días, lo que ocurra primero. Complementa — no reemplaza — `docs/strategic-audit-2026-06-19.md`.*

**Operacionalización (2026-07-05):** este análisis se convirtió en el roadmap ejecutable **[`docs/roadmap-2026-07-05.md`](roadmap-2026-07-05.md)** (que supersede a `docs/roadmap-2026-05-09.md`) y en issues de GitHub: Epic 6 Seguridad (#268 → #272–#276), Epic 7 Escalabilidad (#269 → #277–#279), Epic 8 Adoption Wave (#270 → #280–#283), Epic 9 v1.0 (#271). Milestones re-scopeados: v0.3.0 = Fundaciones (seguridad + escalabilidad); distribución (#220) y marketplace (#221) movidos a v0.4.0. El backlog estructurado (`docs/backlog.yaml`) refleja todo lo anterior.
