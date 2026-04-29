# ClawCrate v3.1.1

### Ejecución segura para agentes AI. Nativo en Linux y macOS. Un binary autocontenido por plataforma.

---

## Resumen Ejecutivo

ClawCrate es un runtime de ejecución segura para agentes AI. Un binary autocontenido en Rust (~15-20MB por plataforma) que aísla comandos generados por LLMs usando **primitivas nativas de sandboxing de cada OS**: Landlock + seccomp en Linux, Seatbelt en macOS. Sin Docker. Sin VMs. Sin permisos de root. Ejecución nativa con overhead mínimo en ambas plataformas — incluyendo Apple Silicon.

**El dolor del usuario es simple:** quieres que tu agente AI corra tests, builds e installs sin acceso implícito a toda tu máquina. Sin tocar tus credenciales, tus keys, ni tus sesiones activas. Y que cada ejecución deje un registro claro de qué se permitió y qué se bloqueó.

**Ejemplo de uso:**

```bash
clawcrate run --profile build -- cargo test
clawcrate run --profile install -- npm install express
clawcrate run --profile safe -- pytest -q
```

El 68.5% de usuarios de OpenClaw están en macOS. ClawCrate es nativo en ambas plataformas desde el día 1, porque la abstracción lo permite y el mercado lo exige.

---

## Tabla de Contenidos

1. [Introducción](#1-introducción)
2. [El Problema](#2-el-problema)
3. [Objetivo del Proyecto](#3-objetivo-del-proyecto)
4. [Landscape Competitivo](#4-landscape-competitivo)
5. [Filosofía de Diseño](#5-filosofía-de-diseño)
6. [Arquitectura Dual-Platform](#6-arquitectura-dual-platform)
7. [El Problema de Red — Tres Soluciones](#7-el-problema-de-red)
8. [UX: Perfiles, No YAML](#8-ux-perfiles-no-yaml)
9. [Replica Mode](#9-replica-mode)
10. [Stack Tecnológico](#10-stack-tecnológico)
11. [Estructura del Proyecto](#11-estructura-del-proyecto)
12. [Contratos de Tipos y Traits](#12-contratos-de-tipos-y-traits)
13. [Implementación Paso a Paso](#13-implementación-paso-a-paso)
14. [Roadmap Detallado](#14-roadmap-detallado)
15. [Plan de Testing](#15-plan-de-testing)
16. [Métricas de Validación](#16-métricas-de-validación)
17. [Distribución y Adopción](#17-distribución-y-adopción)
18. [Riesgos y Mitigaciones](#18-riesgos-y-mitigaciones)
19. [Out-of-Scope](#19-out-of-scope)
20. [Changelog v1 → v2 → v3 → v3.1 → v3.1.1](#20-changelog)

---

## 1. Introducción

Los agentes AI de código — OpenClaw, Claude Code, Codex, Cursor — ejecutan comandos shell, instalan paquetes, modifican archivos y hacen requests de red en tu máquina local. Cada comando hereda todos los permisos del usuario que lo ejecutó.

Esto no es un problema teórico. En febrero de 2026, la extensión Cline de VS Code (5M+ usuarios) fue comprometida por una cadena de prompt injection que exfiltró tokens de npm y publicó un paquete malicioso. En marzo, un investigador demostró que Claude Code podía bypassear su propia denylist usando trucos de path (`/proc/self/root/usr/bin/npx`) y cuando bubblewrap lo atrapó, el agente desactivó el sandbox por completo para completar la tarea.

ClawCrate existe porque **el agente no debería decidir sus propios límites.** La jaula debe ser externa, de kernel, heredable a todos los subprocesos, e imposible de remover desde adentro.

---

## 2. El Problema

### En una frase

> Quieres que el agente haga trabajo útil sin tocar tus secretos ni romper tu máquina.

### Para un dev Linux

Tu agente puede correr builds y tests sin ver `~/.ssh`, `~/.aws` ni tu home. Si un `npm install` trae un postinstall malicioso, ese script no puede leer tus credenciales ni tus variables de entorno sensibles — incluso si tiene acceso a red. Con Replica Mode, el workspace original también queda protegido. El filtrado de red por dominio llega en P1 con el egress proxy; en el alpha, la contención es por filesystem, env scrubbing y replica.

### Para un usuario de Mac (68.5% del mercado OpenClaw)

Usas tu Mac como cockpit. Tu agente corre nativamente en Apple Silicon — sin overhead de VM. Pero el perfil de sandboxing bloquea acceso a paths de secretos del host, incluyendo `~/Library/Keychains`, `~/Library/Cookies`, `~/.ssh` y `~/.aws`. Si algo sale mal, solo se rompe lo que está dentro de la jaula.

### Para un equipo/empresa

Tus automatizaciones no corren como un usuario con permisos amplios. Corren en un entorno mínimo, repetible e inspectable. Cada ejecución genera artifacts con el plan de permisos, los logs completos, y un diff de cambios en filesystem. Las policies son versionables en git.

### Lo que NO es el problema

El problema no es "el ecosistema OpenClaw está en crisis" ni "NVIDIA no resuelve la seguridad." Esos son contextos relevantes pero lejanos al dolor diario del usuario. El problema es inmediato: tu agente tiene demasiados permisos y no tienes una forma simple de recortarlos.

---

## 3. Objetivo del Proyecto

### Visión

ClawCrate es una capa de ejecución segura para agentes AI, apoyada en los mecanismos nativos de sandboxing de cada OS, diseñada para recortar filesystem, procesos, recursos y acceso del entorno sin mover la ejecución a una VM ni depender de Docker.

### Meta del Alpha (6 semanas)

Un binary Rust funcional que:

1. **Planifique** una ejecución evaluando el comando contra un perfil.
2. **Sandboxee** el proceso usando primitivas nativas del OS (Landlock en Linux, Seatbelt en macOS).
3. **Scrubee** variables de entorno sensibles antes de la ejecución.
4. **Capture** stdout/stderr y genere un fs-diff post-ejecución.
5. **Audite** cada decisión en artifacts legibles por ejecución.

### Comandos del alpha

Surface alpha publicada:

```
clawcrate run [--profile PROFILE] [--replica | --direct] -- COMMAND...
clawcrate plan [--profile PROFILE] [--replica | --direct] -- COMMAND...    # dry-run
clawcrate doctor                                                            # diagnóstico del sistema
clawcrate api [--bind ADDR] [--token TOKEN]                                 # API local
clawcrate bridge pennyprompt [--pretty]                                     # bridge CLI
```

> Cada perfil tiene un `default_mode` (Direct o Replica). Los flags permiten override:
> - `--replica` fuerza Replica Mode en perfiles que defaultan a Direct (e.g., `--replica --profile build`).
> - `--direct` fuerza Direct Mode en perfiles que defaultan a Replica (e.g., `--direct --profile install`).
> - Sin flag, se usa el `default_mode` del perfil.

### Lo que NO está en el alpha

- ❌ Host allowlists por dominio (ver sección 7 para roadmap)
- ❌ SQLite como pieza obligatoria
- ❌ Auditoría "append-only chain" como claim central

**El alpha mantiene foco en sandboxing nativo y artifacts file-based; `api` y `bridge` forman parte de la surface publicada y su hardening continúa post-alpha.**

---

## 4. Landscape Competitivo

### 4.1 El dato que importa

La distribución de OS de usuarios OpenClaw (Q1 2026):

| OS | Porcentaje |
|----|-----------|
| macOS | 68.5% |
| Linux (VPS) | 22.1% |
| Windows (WSL2) | 9.4% |

Un producto Linux-only ignora dos tercios del mercado. Un producto macOS-only ignora la infraestructura de producción. ClawCrate es nativo en ambos.

### 4.2 Cómo sandboxean los principales agentes

| Agente | macOS | Linux | Standalone? |
|--------|-------|-------|-------------|
| **Codex (OpenAI)** | Seatbelt (Rust) | Bubblewrap + Landlock (Rust) | No — integrado en Codex |
| **Cursor** | Seatbelt (dinámico, documentado públicamente) | Landlock | No — integrado en Cursor |
| **Claude Code** | Seatbelt via sandbox-runtime | Bubblewrap | No — integrado en Claude Code |
| **NemoClaw (NVIDIA)** | Docker + OpenShell | Docker + Landlock + seccomp | Sí, pero requiere Docker |
| **sx (sandbox-shell)** | Seatbelt | ❌ No soporta Linux | Sí |
| **SandVault** | User account + Seatbelt | ❌ | Sí |
| **Membrane** | Docker + eBPF | Docker + eBPF | Sí, pero requiere Docker |
| **ClawCrate** | **Seatbelt (Rust, nativo)** | **Landlock + seccomp (Rust, nativo)** | **Sí** |

> **Nota:** Para Codex, la evidencia pública incluye código fuente abierto con un backend `macos.seatbelt`. Para Cursor, hay un blog público explicando su decisión de usar Seatbelt. Para Claude Code, Anthropic documenta sandbox-runtime con Seatbelt en macOS.

**El hueco:** No existe un sandbox standalone, sin Docker, nativo en ambas plataformas, escrito en Rust, con perfiles simples y auditoría, diseñado para cualquier agente AI. Cada agente implementó su propio sandboxing interno — ClawCrate externaliza esa capa para que sirva a todos.

### 4.3 Contra sx (sandbox-shell) — el competidor más cercano

`sx` de agentic-dev3o es un CLI Rust que wrappea comandos en Seatbelt en macOS. Es elegante y funcional. Diferencias:

| Aspecto | sx | ClawCrate |
|---------|-----|-----------|
| Plataformas | macOS only | macOS + Linux |
| Auditoría | No | Artifacts por ejecución |
| Plan/dry-run | `--dry-run` genera profile | `clawcrate plan` muestra permisos en lenguaje humano |
| Replica mode | No | Sí — copia filtrada del workspace |
| fs-diff | No | Sí — snapshot pre/post |
| Red | No control (o todo offline, o todo online) | Tres estrategias progresivas (ver sección 7) |
| Doctor | No | Sí — diagnóstico de capabilities del sistema |

### 4.4 Approaches adyacentes: alcless (NTT Labs)

**alcless** (Akihiro Suda / NTT Labs) es un sandbox ligero para macOS basado en un enfoque fundamentalmente distinto: crea un usuario separado del host y ejecuta comandos con las credenciales de ese usuario, sincronizando el workspace vía `rsync`. Es obra de un maintainer de Moby (dockerd), containerd y runc — alguien que conoce profundamente los límites de las herramientas de aislamiento.

alcless valida dos cosas importantes para ClawCrate:

1. **Existe demanda real por sandboxing local ligero en macOS sin VMs.** El propio artículo de NTT Labs posiciona explícitamente el caso de uso de AI agents ejecutando shell commands como motivación central.

2. **El patrón replica + sync-back tiene sentido práctico en macOS.** alcless copia el directorio de trabajo al usuario sandbox, ejecuta el comando, y sincroniza cambios de vuelta con confirmación. Es exactamente el patrón de Replica Mode de ClawCrate (sección 9).

| Aspecto | alcless | ClawCrate |
|---------|---------|-----------|
| Mecanismo de aislamiento | Usuario separado del host + permisos POSIX | Seatbelt kernel-level (macOS) / Landlock+seccomp (Linux) |
| Setup | `sudo` requerido, usuario persistente, configuración manual | Single binary, sin root, sin setup persistente |
| Plataformas | macOS only | macOS + Linux |
| Patrón de workspace | rsync copy + sync-back con confirmación | Replica Mode (similar) + Direct Mode |
| Granularidad de permisos | A nivel de usuario POSIX | A nivel de paths, syscalls, red, recursos |
| Dependencias | Go + su + sudo + rsync | Rust, self-contained |

**Posición de ClawCrate:** alcless demuestra que hay otra escuela de diseño seria en macOS para este problema. ClawCrate toma esa validación conceptual del patrón replica, pero mantiene una dirección distinta: usar los mecanismos nativos de sandboxing del kernel como backend principal y dejar Replica Mode como capa complementaria. Si Apple endureciera la vía de Seatbelt en el futuro, el enfoque de aislamiento por usuario de alcless representa una alternativa pragmática conocida.

---

## 5. Filosofía de Diseño

### 5.1 Principios

1. **Deny by default.** El proceso sandboxeado empieza con cero permisos y recibe solo lo necesario según el perfil.

2. **Plan before execute.** `clawcrate plan` muestra en lenguaje humano qué se permitirá y qué se bloqueará. Sin jerga de kernel.

3. **Perfiles, no YAML.** El usuario compra tranquilidad sin fricción, no archivos de configuración. `--profile safe` es el punto de entrada. YAML es el escape hatch para power users.

4. **Nativo en cada plataforma.** Seatbelt en macOS, Landlock+seccomp en Linux. Mismo codebase Rust (compilación condicional), misma UX, distinto enforcement.

5. **Artifacts, no base de datos.** Cada ejecución genera un directorio con `plan.json`, `result.json`, `stdout.log`, `stderr.log`, `audit.ndjson`, `fs-diff.json`. Legible, portable, versionable. SQLite es P2.

6. **ClawCrate se integra en el boundary donde el agente delega la ejecución de comandos shell.** No envuelve al agente completo — solo aísla cada comando que el agente pide ejecutar. Esa distinción importa para la integración y para el modelo de seguridad.

### 5.2 Modelo de amenazas

**Protege contra:**
- Comandos maliciosos generados por prompt injection
- Paquetes con postinstall scripts que exfiltran secretos
- Lectura de archivos sensibles (`~/.ssh`, `~/.aws`, `~/.gnupg`, Keychain, cookies)
- Escritura fuera del workspace del proyecto
- Fork bombs y resource exhaustion
- Agentes que intentan desactivar el sandbox desde adentro (Seatbelt es irremovible; Landlock también post-restrict_self)

**NO protege contra:**
- Kernel exploits (requiere VM para ese nivel de aislamiento)
- Prompt injection en el LLM (es responsabilidad del agente)
- Exfiltración via POST a un dominio permitido (cuando la red está habilitada)
- Side-channel attacks de CPU

### 5.3 Interfaz de comando

**`clawcrate run -- npm test`**, no `clawcrate run "npm test"`.

El doble guión (`--`) es la convención POSIX para separar opciones del comando. Elimina toda ambigüedad de quoting, parsing y shell expansion. `sh -c "..."` es un escape hatch explícito, no el default.

```bash
# Correcto — sin ambigüedad
clawcrate run --profile build -- cargo test --release

# Escape hatch cuando necesitas shell features (pipes, redirects)
clawcrate run --profile build -- sh -c "cargo test 2>&1 | tee test.log"
```

---

## 6. Arquitectura Dual-Platform

### 6.1 El insight central

macOS y Linux tienen primitivas de sandboxing nativas a nivel de kernel. Ambas son:
- **Irremovibles** desde el proceso sandboxeado
- **Heredables** a todos los subprocesos (fork/exec)
- **De overhead mínimo** (son hooks de kernel, no virtualización)
- **Accesibles sin root** (Landlock desde Linux 5.13; Seatbelt no requiere root para `sandbox-exec`)

La arquitectura de ClawCrate explota esta simetría:

```
ClawCrate (un binary Rust por plataforma)
    │
    ├── Shared (80% del código)
    │     ├── CLI (clap)
    │     ├── Profile engine
    │     ├── Plan generator
    │     ├── Env scrubber
    │     ├── Output capture
    │     ├── fs-diff (snapshot pre/post)
    │     ├── Audit artifacts
    │     └── Doctor framework
    │
    └── Platform-specific (20% del código)
          ├── #[cfg(target_os = "linux")]
          │     ├── Landlock ruleset
          │     ├── seccomp-bpf filter
          │     └── rlimits
          │
          └── #[cfg(target_os = "macos")]
                ├── Seatbelt SBPL generator
                └── rlimits (vía setrlimit)
```

### 6.2 Backend Linux: Landlock + seccomp + rlimits

| Capa | Mecanismo | Qué controla |
|------|-----------|-------------|
| Filesystem | Landlock LSM (ABI v1-v5) | Paths de lectura/escritura/ejecución |
| Syscalls | seccomp-bpf (via seccompiler) | Qué syscalls puede hacer el proceso |
| Recursos | rlimits | CPU, memoria, file descriptors, procesos |
| Red | Cerrada por default en alpha | Sin acceso a red — ver sección 7 para opciones |

**Limitación honesta de Landlock:** Landlock trabaja con jerarquías de paths. Si das `read` a `.` (el workspace), no puedes hacer un `deny` confiable de `**/.env` dentro de ese workspace. Landlock no modela globs intra-jerarquía. **ClawCrate no promete deny intra-workspace en Linux.** Para ese caso, usa Replica Mode (sección 9).

**Landlock capabilities por ABI:**

| ABI | Kernel | Capabilities |
|-----|--------|-------------|
| v1 | 5.13+ | Filesystem read/write/exec |
| v2 | 5.19+ | + File rename/link |
| v3 | 6.2+ | + File truncate |
| v4 | 6.7+ | + Network (TCP bind/connect por puerto) |
| v5 | 6.10+ | + Ioctl restrictions |

ClawCrate opera en best-effort: usa las capabilities disponibles del kernel y reporta la degradación via `clawcrate doctor`.

### 6.3 Backend macOS: Seatbelt

Seatbelt es el mecanismo de sandboxing kernel-enforced de macOS. Es usado por todas las apps del App Store, por Chrome (documentado por el proyecto Chromium), y la evidencia pública muestra que Codex, Cursor y Claude Code lo usan para sandboxing de agentes. Se accede via `sandbox-exec` (CLI) o via `sandbox_init()` (C API).

**Propiedades clave de Seatbelt:**

1. **Irremovible.** Una vez aplicado, el sandbox es permanente para el proceso y todos sus hijos. No hay forma de quitarlo desde adentro.

2. **Last-match-wins con filtros regex.** A diferencia de Landlock, Seatbelt puede hacer deny intra-workspace:
   ```scheme
   (allow file-read* (subpath "/Users/dev/proyecto"))
   (deny file-read* (subpath "/Users/dev/proyecto/.env"))
   (deny file-read* (regex #"\.env\.local$"))
   (deny file-read* (subpath "/Users/dev/proyecto/.git/config"))
   ```
   Esto permite dar acceso al proyecto pero bloquear archivos específicos dentro de él.

3. **Ejecución nativa.** El proceso sandboxeado no pasa por virtualización ni emulación. En Apple Silicon, eso significa ejecución directa sin overhead de VM.

4. **SBPL (Sandbox Profile Language) es Scheme-like.** ClawCrate genera perfiles SBPL dinámicamente en runtime desde los profiles:

```scheme
;; Generado por ClawCrate para: cargo test --release
;; Profile: build | Workspace: /Users/dev/myproject

(version 1)
(deny default)

;; Binarios del sistema necesarios
(allow process-exec
  (subpath "/usr/bin")
  (subpath "/usr/local/bin")
  (subpath "/opt/homebrew/bin"))

;; Lectura del sistema
(allow file-read*
  (subpath "/usr")
  (subpath "/System")
  (subpath "/Library")
  (subpath "/opt/homebrew"))

;; Workspace: lectura completa
(allow file-read* (subpath "/Users/dev/myproject"))

;; Workspace: escritura solo en target/
(allow file-write* (subpath "/Users/dev/myproject/target"))

;; Deny explícito de secretos dentro del workspace
(deny file-read* (subpath "/Users/dev/myproject/.env"))
(deny file-read* (regex #"/\.env(\..+)?$"))
(deny file-read* (subpath "/Users/dev/myproject/.git/config"))

;; Secretos del host bloqueados
(deny file-read* (subpath "/Users/dev/.ssh"))
(deny file-read* (subpath "/Users/dev/.aws"))
(deny file-read* (subpath "/Users/dev/.gnupg"))
(deny file-read* (subpath "/Users/dev/.docker"))
(deny file-read* (subpath "/Users/dev/Library/Keychains"))
(deny file-read* (subpath "/Users/dev/Library/Cookies"))

;; Temp
(allow file-write* (subpath "/tmp"))
(allow file-write* (subpath "/private/tmp"))

;; Red: denegada por default
(deny network*)

;; Metadata global (requerido para que getaddrinfo funcione si se habilita red)
(allow file-read-metadata)

;; Sysctl (requerido por muchos procesos)
(allow sysctl-read)
```

5. **Estado de deprecación — tratamiento honesto.** Lo deprecado es la CLI `sandbox-exec`, no el sandboxing kernel-enforced de macOS. Lo tratamos como una dependencia pragmática y vigente hoy, con riesgo de compatibilidad futura que monitoreamos explícitamente. La base para esta decisión:
   - El proyecto Chromium documenta explícitamente el uso de Seatbelt en macOS.
   - Cursor publicó un blog explicando su decisión de usar Seatbelt vía `sandbox-exec`.
   - Codex (OpenAI) tiene código abierto con un backend `seatbelt`.
   - Claude Code usa `sandbox-runtime` con Seatbelt en macOS.
   - Apple sigue usando Seatbelt internamente para App Sandbox — el mecanismo de kernel no muestra señales de desaparecer.
   - Si Apple cambiara la interfaz pública, existe una alternativa pragmática conocida en macOS: aislamiento por usuario separado + replica/sync, como demuestra alcless (NTT Labs). Ver sección 4.4.

### 6.4 Tabla comparativa de backends

| Capacidad | Linux (Landlock+seccomp) | macOS (Seatbelt) |
|-----------|-------------------------|-------------------|
| Filesystem deny jerárquico | ✅ | ✅ |
| Deny intra-workspace (.env dentro de .) | ❌ (usa Replica Mode) | ✅ (regex-based deny) |
| Restricción de syscalls | ✅ seccomp-bpf (filtrado granular por syscall) | Parcial (Seatbelt restringe operaciones del proceso, pero con granularidad distinta a seccomp) |
| Control de red por puerto | ✅ (Landlock ABI v4+, kernel 6.7+) | ❌ (solo deny/allow global) |
| Control de red por hostname | ❌ | ❌ |
| rlimits (CPU, mem, fds) | ✅ | ✅ |
| Irremovible post-apply | ✅ | ✅ |
| Herencia a subprocesos | ✅ | ✅ |
| Sin root | ✅ (desde kernel 5.13) | ✅ |

> **Nota sobre simetría:** Landlock+seccomp y Seatbelt no son mecanismos equivalentes. seccomp-bpf filtra syscalls individuales con precisión; Seatbelt opera a un nivel más alto con categorías de operaciones (file-read*, network*, process-exec). Ambos logran el objetivo de defense-in-depth, pero con granularidades distintas. ClawCrate abstrae estas diferencias detrás del trait `SandboxBackend`.

---

## 7. El Problema de Red — Tres Soluciones

Ni Seatbelt ni Landlock (antes de ABI v4) ofrecen control granular de red por hostname. Puedes bloquear toda la red o permitir toda la red, pero no puedes decir "permite solo `registry.npmjs.org`" a nivel de kernel.

Esto es un problema real para el perfil `install` (necesita descargar dependencias) y `build` cuando necesita crates.io, npm, o pypi.

### Tres soluciones, ordenadas de mejor a peor:

### Solución A: Egress Proxy Local (⭐ Recomendada para P1)

**Cómo funciona:**

```
┌────────────────────────────────┐
│  Proceso sandboxeado           │
│  (toda red bloqueada excepto   │
│   localhost)                   │
│                                │
│  HTTP_PROXY=localhost:19876    │
│  HTTPS_PROXY=localhost:19876   │
└──────────┬─────────────────────┘
           │ solo puede hablar con localhost
           ▼
┌────────────────────────────────┐
│  ClawCrate Egress Proxy        │
│  (corre FUERA del sandbox)     │
│                                │
│  • Recibe HTTP CONNECT         │
│  • Lee hostname del TLS SNI    │
│  • Compara contra allowlist    │
│  • Si match: tunnel through    │
│  • Si no match: 403 Forbidden  │
│  • Log todo a audit.ndjson     │
└────────────────────────────────┘
```

**Por qué es la mejor:**

- **Enforcement real.** El kernel bloquea toda conexión directa excepto localhost. Un proceso que ignore `HTTP_PROXY` simplemente no puede conectarse — recibe `EPERM`.
- **Control por hostname.** El proxy lee el hostname del ClientHello TLS (SNI peek) sin descifrar el tráfico. Sin MITM, sin CA cert, sin inspección de contenido.
- **Logging completo.** Cada conexión (permitida o denegada) queda en el audit log.
- **Pattern probado.** Es lo que hacen Goose Desktop, agent-seatbelt-sandbox, Codex sandbox-runtime, y Claude Code sandbox. Es el estándar de facto en el ecosistema de sandboxing de agentes.

**Implementación en Rust:** Un mini HTTP CONNECT proxy en tokio (200-400 líneas). Se implementa en P1, no es necesario para el alpha.

**Debilidad:** Depende de que las herramientas respeten `HTTP_PROXY`. La mayoría lo hace (curl, wget, npm, pip, cargo, git, Python requests). Node.js necesita `NODE_OPTIONS="--use-env-proxy"` (Node 20.18+). Herramientas que usen sockets directos y no respeten proxy simplemente fallarán — lo cual es el comportamiento correcto para un sandbox deny-by-default.

### Solución B: DNS Interception (Ingeniosa pero más compleja)

**Cómo funciona:** En lugar de proxy HTTP, intercepta DNS. Los procesos sandboxeados usan un DNS resolver local (fuera del sandbox) que resuelve hostnames en la allowlist normalmente y retorna `NXDOMAIN` para el resto.

**Ventaja:** Funciona para cualquier protocolo (HTTP, HTTPS, SSH, git://), no solo HTTP.

**Desventajas:**
- **Bypasseable.** Un proceso puede hardcodear una IP y saltarse DNS. El proxy de Solución A no tiene este problema porque el kernel bloquea toda conexión directa.
- **Más compleja.** DNS server, TTLs, CNAME chains, asegurar que el resolver del sandbox apunte al correcto.
- **CDNs volátiles.** Un hostname puede resolver a IPs diferentes cada minuto.

**Mitigación:** Combinar DNS interception con iptables/nftables (Linux) que bloqueen conexiones a IPs no resueltas por el resolver local. Esto es lo que hace Membrane. Pero añade complejidad operativa.

### Solución C: Perfiles de Red Simples — Solo 2 Niveles (Alpha)

**Cómo funciona en el alpha:**

```
none       Red completamente bloqueada (default para safe y build)
open       Red abierta (para install y open, con warning explícito)
```

Cuando la red está en `open`, ClawCrate muestra un warning claro:

```bash
$ clawcrate run --profile install -- npm install express
[clawcrate] ⚠ Profile 'install' habilita acceso a red sin filtrado por dominio.
[clawcrate]   Modo replica activado: el workspace original está protegido.
[clawcrate]   Usa --direct para ejecutar sobre el workspace real (no recomendado).
```

**Por qué es la mínima viable:** Zero complejidad adicional. Honesto. Sin promesas falsas.

### Recomendación para el roadmap

| Fase | Solución de red |
|------|----------------|
| Alpha (semanas 1-6) | **Solución C**: `none` y `open`. Honesto, funcional. |
| P1 (semanas 7-10) | **Solución A**: Egress proxy local con SNI filtering. |
| P2 (futuro) | **Solución A + B combinadas**: Proxy + DNS para otros protocolos. |

---

## 8. UX: Perfiles, No YAML

### 8.1 Cuatro perfiles built-in

| Perfil | Filesystem | Red | Env vars | Replica | Caso de uso |
|--------|-----------|-----|----------|---------|-------------|
| **safe** | Read: workspace. Write: ninguno. | `none` | Scrubbed | Opcional | Tests read-only, linting, análisis, git status |
| **build** | Read: workspace + toolchain. Write: output dirs (`target/`, `dist/`, `coverage/`). | `none` | Scrubbed | Opcional | Compilación, tests, coverage |
| **install** | Read: workspace. Write: dependency dirs (`node_modules/`, `.venv/`). | `open` (con warning) | Scrubbed | **Default** (opt-out con `--direct`) | npm install, pip install, cargo fetch |
| **open** | Read/Write: workspace completo. | `open` | Parcialmente scrubbed | Opcional | Scripts de propósito general |

> **`install` usa Replica Mode por default.** Es el caso de mayor riesgo: postinstall scripts con acceso a red ejecutándose sobre tu workspace. En lugar de confiar en que el usuario recuerde un flag, el perfil materializa `WorkspaceMode::Replica` automáticamente. Para ejecutar sobre el workspace real, el usuario debe hacer opt-out explícito con `--direct`:
> ```bash
> # Default: replica mode (seguro)
> clawcrate run --profile install -- npm install express
>
> # Opt-out explícito: direct mode (el usuario acepta el riesgo)
> clawcrate run --direct --profile install -- npm install express
> ```

### 8.2 Qué se scrubbea siempre

Independientemente del perfil, estas variables de entorno **nunca** llegan al proceso hijo:

```
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
GITHUB_TOKEN, GH_TOKEN, GITLAB_TOKEN
ANTHROPIC_API_KEY, OPENAI_API_KEY
NPM_TOKEN, PYPI_TOKEN
SSH_AUTH_SOCK
GOOGLE_APPLICATION_CREDENTIALS
DATABASE_URL
Cualquier variable que matchee: *_SECRET*, *_PASSWORD*, *_KEY, *_TOKEN
```

El scrubbing es una capa adicional sobre el sandbox de filesystem. Incluso si un bypass de sandbox permitiera leer archivos de credenciales, las variables de entorno correspondientes no estarían presentes.

### 8.3 YAML como escape hatch

Para power users que necesitan control granular:

```yaml
# .clawcrate/custom.yaml
name: my-project
extends: build

filesystem:
  write:
    - "./custom-output-dir"
  deny:                        # Solo en macOS (Seatbelt regex)
    - ".env"
    - ".env.local"
    - ".env.production"

environment:
  passthrough:
    - "MY_CUSTOM_VAR"

resources:
  max_cpu_seconds: 300
  max_memory_mb: 4096
```

```bash
clawcrate run --profile .clawcrate/custom.yaml -- cargo test
```

---

## 9. Replica Mode

### El problema que resuelve

En Linux, Landlock no puede hacer deny intra-workspace. Si necesitas que el agente lea `./src/` pero no `./.env` dentro del mismo directorio, Landlock no puede expresar eso.

En macOS, Seatbelt sí puede (regex-based deny). Pero hay otro problema: ¿y si el agente necesita escribir en el workspace pero quieres proteger archivos sensibles que están dentro?

**Replica mode** resuelve ambos casos de forma uniforme en ambas plataformas.

### Cómo funciona

```bash
# install activa replica automáticamente (es su default_mode)
clawcrate run --profile install -- npm install express

# otros perfiles pueden activar replica explícitamente
clawcrate run --replica --profile build -- cargo test
```

1. ClawCrate crea un directorio temporal (e.g., `/tmp/clawcrate/exec_a1b2c3/workspace/`)
2. Copia el workspace al directorio temporal, **excluyendo** archivos sensibles:
   - `.env`, `.env.*`
   - `.git/config` (puede contener tokens)
   - Archivos listados en `.clawcrateignore` (análogo a `.gitignore`)
3. El sandbox ejecuta el comando en la copia
4. ClawCrate genera un diff de cambios
5. **Aplicar cambios de vuelta al workspace real siempre requiere confirmación explícita del usuario. Nunca ocurre automáticamente.**

### Validación del patrón

El patrón replica + sync-back está validado por herramientas como alcless (NTT Labs), que usa un enfoque similar de copiar el workspace a un contexto aislado y sincronizar cambios de vuelta con confirmación. ClawCrate busca una UX más simple (sin usuario persistente, sin sudo) y un modelo más uniforme entre Linux y macOS.

### Cuándo usar replica vs direct

| Modo | Cuándo usarlo |
|------|--------------|
| **direct** (default) | Tests read-only, builds normales, linting. No hay secretos intra-workspace que proteger. |
| **replica** (recomendado para install) | npm install, pip install, builds en repos con `.env`, cualquier comando con write + red habilitada. |

### Costo y mitigaciones

La copia del workspace toma tiempo y espacio. Para proyectos grandes (>1GB), puede ser significativo.
- **Hardlinks** donde el filesystem lo permita (mismo volumen, APFS/ext4)
- **Copia selectiva**: solo copiar lo que el comando necesita
- **Cache**: reutilizar copias entre ejecuciones del mismo commit

Para repos pequeños y medianos (<500MB), el overhead es aceptable — en el rango de 1-3 segundos en SSDs modernos.

---

## 10. Stack Tecnológico

### 10.1 Crates

| Crate | Propósito | Plataforma |
|-------|-----------|-----------|
| **clap** 4.x | CLI parsing, derive macros | Ambas |
| **serde** + **serde_yaml** + **serde_json** | Serialización | Ambas |
| **tracing** + **tracing-subscriber** | Structured logging | Ambas |
| **nix** 0.29.x | fork, exec, rlimits, pipes, signals | Ambas |
| **sha2** 0.10.x | Hashing para audit integrity | Ambas |
| **comfy-table** 7.x | CLI output formatting | Ambas |
| **thiserror** 2.x | Error types | Ambas |
| **chrono** 0.4.x | Timestamps | Ambas |
| **walkdir** 2.x | fs-diff snapshot | Ambas |
| **landlock** 0.4.x | Filesystem sandbox | Linux only |
| **seccompiler** 0.4.x | Syscall filtering (de AWS/Firecracker) | Linux only |
| **tokio** 1.x (minimal) | Solo para P1: egress proxy | Ambas (P1) |

### 10.2 Exclusiones

| No | Motivo |
|----|--------|
| SQLite (en alpha) | Artifacts en disco son más simples y suficientes. P2. |
| wasmtime | WASI no soporta runtimes nativos. Fuera de scope. |
| Docker | Contradice la tesis del proyecto. |
| notify (watcher) | fs-diff usa snapshot pre/post, no watcher. Más robusto para auditoría. |

### 10.3 Builds

| Target | Binary | Nota |
|--------|--------|------|
| `x86_64-unknown-linux-musl` | `clawcrate-linux-x86_64` | Static, zero runtime deps |
| `aarch64-unknown-linux-musl` | `clawcrate-linux-aarch64` | Static, zero runtime deps |
| `aarch64-apple-darwin` | `clawcrate-macos-arm64` | Apple Silicon nativo |
| `x86_64-apple-darwin` | `clawcrate-macos-x86_64` | Intel Mac |

**musl en Linux**, no glibc+crt-static. En macOS, binaries nativos por arquitectura.

---

## 11. Estructura del Proyecto

```
clawcrate/
├── Cargo.toml                         # Workspace root
├── rust-toolchain.toml
├── LICENSE (MIT)
├── README.md
│
├── crates/
│   ├── clawcrate-types/               # Tipos compartidos
│   ├── clawcrate-profiles/            # Profile engine + presets
│   ├── clawcrate-sandbox/             # Abstracción sobre backends
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── traits.rs              # trait SandboxBackend
│   │       ├── linux.rs               # #[cfg(target_os = "linux")]
│   │       ├── darwin.rs              # #[cfg(target_os = "macos")]
│   │       ├── env_scrub.rs           # Variable scrubbing (cross-platform)
│   │       ├── rlimits.rs             # Resource limits (cross-platform)
│   │       └── doctor.rs              # System capability detection
│   ├── clawcrate-capture/             # stdout/stderr capture + fs-diff
│   ├── clawcrate-audit/               # Artifact generation (ndjson)
│   └── clawcrate-cli/                 # CLI entry point
│
├── profiles/                          # Built-in profiles
│   ├── safe.yaml
│   ├── build.yaml
│   ├── install.yaml
│   └── open.yaml
│
├── fixtures/                          # Test fixtures
│   ├── malicious_postinstall/
│   ├── exfiltration_attempt/
│   ├── env_leak/
│   ├── sandbox_escape/
│   ├── resource_exhaustion/
│   └── benign_project/
│
└── docs/
    ├── architecture.md
    ├── profiles-reference.md
    ├── kernel-requirements.md
    └── integration-guide.md
```

---

## 12. Contratos de Tipos y Traits

### 12.1 Trait central: SandboxBackend

```rust
pub trait SandboxBackend: Send + Sync {
    /// Genera la configuración de sandbox para la plataforma
    fn prepare(&self, plan: &ExecutionPlan) -> anyhow::Result<SandboxConfig>;

    /// Lanza el comando dentro del sandbox y devuelve el handle del child process.
    /// Cada backend decide su estrategia de lanzamiento:
    ///   - Linux: fork → apply Landlock/seccomp in-process → exec
    ///   - macOS: exec via sandbox-exec con SBPL generado (reemplaza el proceso)
    fn launch(
        &self,
        config: &SandboxConfig,
        command: &[String],
        capture: &CaptureConfig,
    ) -> anyhow::Result<SandboxedChild>;

    /// Reporta las capabilities del sistema
    fn probe(&self) -> SystemCapabilities;
}

/// Handle opaco del proceso sandboxeado
pub struct SandboxedChild {
    pub pid: u32,
    pub stdout: std::process::ChildStdout,
    pub stderr: std::process::ChildStderr,
}
```

### 12.2 Tipos core

```rust
/// Intención del perfil — sin paths, sin estado de runtime.
/// Se resuelve a WorkspaceMode cuando se construye el ExecutionPlan.
pub enum DefaultMode {
    Direct,
    Replica,
}

/// Estado materializado de la ejecución — con paths concretos.
/// Construido al armar el ExecutionPlan a partir de DefaultMode + CLI flags.
pub enum WorkspaceMode {
    Direct,
    Replica { source: PathBuf, copy: PathBuf },
}

pub struct ResolvedProfile {
    pub name: String,
    pub fs_read: Vec<PathBuf>,
    pub fs_write: Vec<PathBuf>,
    pub fs_deny: Vec<String>,          // Globs — enforcement depende de plataforma
    pub net: NetLevel,
    pub env_scrub: Vec<String>,
    pub env_passthrough: Vec<String>,
    pub resources: ResourceLimits,
    pub default_mode: DefaultMode,     // install → Replica, el resto → Direct
}

pub struct ExecutionPlan {
    pub id: String,
    pub command: Vec<String>,          // ["cargo", "test", "--release"]
    pub cwd: PathBuf,
    pub profile: ResolvedProfile,
    pub mode: WorkspaceMode,           // materializado con paths reales
    pub actor: Actor,
    pub created_at: DateTime<Utc>,
}

pub enum NetLevel { None, Open }       // Alpha. P1 añade Filtered.

pub struct ExecutionResult {
    pub id: String,
    pub exit_code: Option<i32>,
    pub status: Status,
    pub duration_ms: u64,
    pub artifacts_dir: PathBuf,
}

pub enum Status {
    Success,
    Failed,
    Timeout,
    Killed,
    SandboxError(String),
}
```

> **Flujo de materialización:** `ResolvedProfile.default_mode` es `DefaultMode` (intención, sin paths). Cuando ClawCrate construye el `ExecutionPlan`, evalúa `default_mode` + CLI flags (`--replica` / `--direct`) y materializa `WorkspaceMode` con paths concretos: si Replica, crea `/tmp/clawcrate/exec_{id}/workspace/`, copia el workspace filtrado, y setea `source` y `copy`. Si Direct, no crea nada. Así `ResolvedProfile` nunca carga estado de runtime que no le pertenece.

### 12.3 Artifacts por ejecución

```
~/.clawcrate/runs/exec_a1b2c3/
├── plan.json           # Plan completo con permisos
├── result.json         # Exit code, duración, status
├── stdout.log          # stdout completo
├── stderr.log          # stderr completo
├── audit.ndjson        # Eventos de auditoría (una línea JSON por evento)
└── fs-diff.json        # Archivos creados/modificados/eliminados
```

---

## 13. Implementación Paso a Paso

### Paso 1: Scaffold + tipos (Días 1-3)

- Crear workspace con todos los crates
- Implementar `clawcrate-types` completo
- CI: `cargo fmt`, `cargo clippy`, `cargo test`
- **Gate:** `cargo check --workspace` pasa

### Paso 2: Profile engine (Días 4-7)

- Parser de profiles YAML (safe, build, install, open)
- Resolver que toma profile + workspace path → `ResolvedProfile`
- Auto-detección de stack (Cargo.toml → Rust, package.json → Node)
- `clawcrate plan --profile build -- cargo test` imprime plan legible
- **Gate:** Plan output correcto para los 4 profiles

### Paso 3: Env scrubbing + rlimits (Días 8-10)

- Scrubber que filtra variables sensibles del entorno
- rlimits aplicados via `setrlimit` (cross-platform)
- Tests unitarios para scrubbing
- **Gate:** Variables sensibles nunca llegan al child process

### Paso 4: Sandbox Linux — Landlock + seccomp (Días 11-16)

- `LinuxSandbox::prepare()` → genera Landlock ruleset + seccomp filter
- `LinuxSandbox::launch()` → fork, aplica rlimits + Landlock + seccomp in-process, exec
- seccomp profile baseline: bloquea `ptrace`, `mount`, `reboot`, permite I/O normal
- Tests en Linux: proceso no puede leer `~/.ssh`, no puede hacer `ptrace`
- **Gate:** Security fixtures pasan en Linux

### Paso 5: Sandbox macOS — Seatbelt (Días 17-22)

- `DarwinSandbox::prepare()` → genera SBPL profile string
- `DarwinSandbox::launch()` → exec via `sandbox-exec` con SBPL generado
- SBPL generado dinámicamente desde `ResolvedProfile`
- Deny intra-workspace validado en los fixtures soportados
- Tests en macOS: proceso no puede leer `~/.ssh`, no puede leer `.env` dentro del workspace
- **Gate:** Security fixtures pasan en macOS

### Paso 6: Runner + capture + fs-diff (Días 23-28)

- Fork → apply sandbox → exec (Linux) / exec via sandbox-exec (macOS)
- Pipes para capturar stdout/stderr
- fs-diff: snapshot pre-ejecución (walkdir + metadata), snapshot post, diff
- `clawcrate run --profile build -- cargo test` funciona end-to-end
- **Gate:** Ejecución completa con artifacts correctos en ambas plataformas

### Paso 7: Replica mode (Días 29-32)

- Copia filtrada del workspace a tmp
- `.clawcrateignore` parser
- Exclusión de `.env*`, `.git/config`
- Diff de cambios con confirmación explícita para sync-back
- **Gate:** Replica mode funcional en ambas plataformas

### Paso 8: Doctor + CLI polish (Días 33-37)

- `clawcrate doctor`: detecta Landlock ABI, seccomp, sandbox-exec, macOS version
- Output human-readable con ✅/⚠️/❌
- `--json` flag para output máquina en todos los comandos
- Error messages claros y accionables
- **Gate:** Doctor reporta correctamente en Linux y macOS

### Paso 9: Docs + release (Días 38-42)

- README.md con quickstart para ambas plataformas
- profiles-reference.md, kernel-requirements.md, integration-guide.md
- Binaries (musl en Linux, nativo en macOS)
- CHANGELOG.md
- **Gate:** Un usuario externo puede instalar y usar en <5 minutos

---

## 14. Roadmap Detallado

### Alpha (Semanas 1-6)

| Semana | Foco |
|--------|------|
| **S1** | Tipos + Profiles + Env scrub + rlimits |
| **S2** | Linux sandbox (Landlock+seccomp) + macOS sandbox (Seatbelt) |
| **S3** | Runner + capture + fs-diff end-to-end |
| **S4** | Replica mode + artifacts completos |
| **S5** | Doctor + CLI polish + JSON output |
| **S6** | Docs + cross-platform tests + release |

> **Nota sobre el cronograma:** Este plan tiene margen estrecho. Las semanas 1-4 son el camino crítico — particularmente la semana 2, que requiere ambos backends sandbox pasando security fixtures. Las semanas 5-6 (polish + docs) funcionan como buffer real: si los backends se deslizan, se absorbe ahí recortando polish, no funcionalidad core. El riesgo principal es la integración cross-platform y la generación de SBPL correcta para macOS, que solo se puede validar en CI con runners macOS reales.

### Post-Alpha

| Item | Fase | Descripción |
|------|------|-------------|
| Egress proxy local | P1 | Solución A de red: proxy HTTP CONNECT con SNI filtering |
| Perfiles community | P1 | Repositorio de profiles contribuidos |
| Approval workflow | P1 | Prompt interactivo cuando un comando excede el perfil |
| SQLite para auditoría | P2 | Migrar de artifacts-en-disco a SQLite indexable |
| API HTTP local | P2 | Hardening de concurrencia/autenticación y contrato de integración |
| Integración con PennyPrompt | P2 | Hardening del bridge y contrato estable para integradores |
| DNS interception | P2 | Solución B de red como complemento del proxy |
| Windows (WSL2) | P3 | Soporte de Landlock/seccomp dentro de WSL2 |

---

## 15. Plan de Testing

### 15.1 Tests de integración (cross-platform)

| Escenario | Linux | macOS |
|-----------|-------|-------|
| Lectura de `~/.ssh/id_rsa` bloqueada | ✅ Landlock deny | ✅ Seatbelt deny |
| Escritura fuera de workspace bloqueada | ✅ Landlock deny | ✅ Seatbelt deny |
| `.env` dentro de workspace bloqueada | ⚠️ Solo con replica mode | ✅ Seatbelt regex deny |
| Fork bomb contenida | ✅ RLIMIT_NPROC | ✅ RLIMIT_NPROC |
| Proceso timeout killed | ✅ RLIMIT_CPU | ✅ RLIMIT_CPU |
| Red bloqueada en profile safe | Bloqueo según backend disponible | ✅ Seatbelt `(deny network*)` |
| Env vars sensibles no presentes | ✅ env scrub | ✅ env scrub |
| `cargo test` exitoso con profile build | ✅ | ✅ |
| fs-diff refleja cambios reales | ✅ | ✅ |
| Replica mode excluye .env | ✅ | ✅ |
| Replica sync-back requiere confirmación | ✅ | ✅ |

### 15.2 Security fixtures

```
fixtures/
├── malicious_postinstall/       # postinstall: "cat ~/.ssh/id_rsa > /tmp/stolen"
├── exfiltration_attempt/        # urllib.request a evil.com
├── env_leak/                    # echo $AWS_SECRET_ACCESS_KEY
├── sandbox_escape/              # Intenta desactivar sandbox
├── resource_exhaustion/         # Fork bomb, memory hog
└── benign_project/              # Proyecto Node.js funcional
```

---

## 16. Métricas de Validación

### Técnicas (targets para benchmark interno)

| Métrica | Target |
|---------|--------|
| Overhead sandbox | Mínimo — benchmark en CI, optimizar si >50ms p95 |
| Tamaño binary (Linux musl) | < 15MB |
| Tamaño binary (macOS) | < 12MB |
| fs-diff latencia (1000 archivos) | Aceptable para repos pequeños/medianos |
| Replica mode copy (100MB workspace) | Aceptable en SSDs modernos |

### Producto

| Métrica | Target |
|---------|--------|
| Time-to-first-run | < 2 minutos |
| Funciona en macOS sin configuración extra | ✅ |
| Funciona en Linux sin root | ✅ (kernel 5.13+) |
| Security fixtures pasan al 100% | ✅ |

---

## 17. Distribución y Adopción

### Instalación

```bash
# macOS (homebrew, post-alpha)
brew install clawcrate

# macOS / Linux (curl one-liner)
curl -fsSL https://clawcrate.dev/install.sh | sh

# Rust ecosystem
cargo install clawcrate
```

### Mensaje por audiencia

| Audiencia | Mensaje |
|-----------|---------|
| Dev Linux | Tu agente puede correr builds y tests sin ver `~/.ssh`, `~/.aws` ni tu home. |
| Dev macOS | Ejecución nativa en Apple Silicon. El perfil bloquea secretos del host incluyendo Keychain y cookies. |
| Equipo | Automatizaciones en entorno mínimo, repetible, auditable. Policies en git. |

### Integración

ClawCrate se integra en el boundary donde el agente delega la ejecución de comandos shell. No envuelve al agente completo — aísla cada comando individual:

```bash
# El agente pide ejecutar "npm test" — el orquestador lo delega a ClawCrate
clawcrate run --profile build -- npm test

# El agente pide instalar dependencias — replica mode es automático para install
clawcrate run --profile install -- npm install express

# En CI, el pipeline wrappea las tool calls del agente
clawcrate run --json --profile safe -- pytest -q
```

Compatible con cualquier agente que ejecute comandos shell: OpenClaw, Claude Code, Codex, Cursor, Gemini CLI, o scripts custom.

---

## 18. Riesgos y Mitigaciones

| Riesgo | Prob. | Impacto | Mitigación |
|--------|-------|---------|-----------|
| **sandbox-exec deprecado/removido por Apple** | **Media** | Alto | Mantener compat matrix por versión de macOS. Tests CI en cada macOS release. Plan de migración documentado. Alternativa conocida: aislamiento por usuario (modelo alcless). |
| **Landlock no disponible en kernel viejo** | Media | Alto | `clawcrate doctor` detecta y advierte. Documentar kernel 5.13+. |
| **Perfiles demasiado restrictivos** | Alta | Medio | `clawcrate plan` para preview. Perfiles calibrados. Mensajes de error claros y accionables. |
| **SBPL syntax frágil / bugs de escaping** | Media | Medio | Test suite exhaustiva de SBPL generado. Tests en múltiples versiones de macOS. |
| **Replica mode lento en proyectos grandes** | Media | Bajo | Hardlinks, copia selectiva, cache. |
| **Competidor lanza algo similar** | Baja | Medio | First-mover dual-platform. Community profiles. Integración con PennyPrompt. |

---

## 19. Out-of-Scope

- ❌ **Windows nativo** — WSL2 usa el backend Linux. Windows nativo es P3.
- ❌ **VM isolation** — ClawCrate es defense-in-depth a nivel de kernel, no VM.
- ❌ **Interceptación de prompts del LLM** — Solo aísla la ejecución de comandos.
- ❌ **Plugin marketplace** — Profiles YAML en un repo.
- ❌ **TLS inspection** — El egress proxy (P1) lee SNI, no descifra tráfico.
- ❌ **Dashboard web** — Artifacts en disco + CLI es suficiente para alpha.
- ❌ **Multi-tenant** — Single user, single machine.

---

## 20. Changelog

### v2 → v3: Calibración editorial

| Cambio | Sección | Razón |
|--------|---------|-------|
| "Un solo binary" → "Un binary autocontenido por plataforma" | Resumen | Hay 4 targets distintos, no un universal binary |
| "Rendimiento 100% nativo" → "Ejecución nativa con overhead mínimo" | Resumen, §6.3 | Sin mediciones todavía, no defender absolutos |
| Removido "Neural Engine, GPU Metal" | §6.3 | No suma al caso de uso, es marketing especulativo |
| "no puede tocar tu Keychain" → "el perfil bloquea acceso a paths de secretos del host incluyendo Keychain y cookies" | §2 | Más preciso, menos absoluto |
| Visión cambiada a "capa de ejecución segura apoyada en mecanismos nativos" | §3 | Menos comparación institucional, más producto |
| Añadida nota de evidencia para Codex/Cursor/Claude Code | §4.2 | Distinguir blog público vs inferencia |
| **Añadido alcless (NTT Labs) en landscape** | §4.4 | Valida patrón replica+sync-back, referencia seria de macOS sandboxing alternativo, contingencia si Seatbelt cambia |
| Seatbelt deprecación tratada como "dependencia pragmática con riesgo monitoreado" | §6.3 punto 5 | Calibrar entre "no hay problema" y "riesgo fatal" |
| "Deny de syscalls" → "Restricción de operaciones del proceso" para Seatbelt | §6.4 | Seatbelt no es simétrico a seccomp |
| Añadida nota sobre asimetría Landlock/seccomp vs Seatbelt | §6.4 | Honestidad técnica |
| Removido "ClawCrate Pro (próximamente)" | §7 Sol. C | Pricing antes de tiempo resta seriedad |
| **`install` ahora recomienda `--replica` por default** | §8.1 | Es el caso más riesgoso, merece la UX más segura |
| Ejemplo principal cambiado a incluir `--replica` en install | Resumen | Coherencia con la recomendación |
| "Deny intra-workspace funcional" → "validado en fixtures soportados" | §13 paso 5 | Más preciso, menos absoluto |
| Red en Linux safe: "según backend disponible" en vez de "seccomp/Landlock v4" | §15.1 | Alpha es none/open, no prometer lo que no está |
| Métricas cambiadas a "targets para benchmark interno" | §16 | No son promesas editoriales, son objetivos internos |
| Integración reescrita como "boundary de delegación de comandos" | §5.1, §17 | ClawCrate no wrappea al agente, aísla sus tool calls |
| Riesgo sandbox-exec subido a **Media** con mitigación reforzada | §18 | Incluye compat matrix, CI por macOS version, plan de migración, y alcless como alternativa conocida |
| Replica sync-back requiere confirmación explícita | §9 | Seguridad + reducción de ansiedad de usuario |
| Añadida mención de alcless en Replica Mode | §9 | Validación del patrón por otra herramienta seria |
| Añadida mención de alcless en Riesgos | §18 | Contingencia documentada si Seatbelt cambia |

### v1 → v2: Cambios estructurales

| Aspecto | v1 | v2+ | Razón |
|---------|-----|-----|-------|
| Plataformas | Linux-only | Dual-platform nativo | 68.5% macOS |
| Backend macOS | Mencionado vagamente | Seatbelt SBPL generator | Validado por Codex/Cursor/Claude Code |
| CLI interface | `run "cmd"` | `run -- cmd args` | Elimina ambigüedad |
| UX principal | Policy YAML | Perfiles built-in | Menos fricción |
| Deny intra-workspace | Prometido con Landlock | Seatbelt regex (macOS) + Replica (Linux) | Honesto por plataforma |
| Red por hostname | Allowlist sin enforcement | 3 soluciones documentadas, alpha solo none/open | Sin promesas falsas |
| Auditoría | SQLite + SHA-256 chain | Artifacts en disco | Más simple, suficiente |
| fs-diff | notify watcher | Snapshot pre/post | Más robusto |
| Binary estático | glibc + crt-static | musl en Linux | Claim real |
| Alpha scope | 5 workflows + API + todo | Surface publicada: run, plan, doctor, api, bridge | Coherencia con el binario real |

### v3 → v3.1: Correcciones de contrato y honestidad del alpha

| Cambio | Sección | Razón |
|--------|---------|-------|
| `install` materializa `Replica` como propiedad del perfil, no como flag opcional | §8.1, §12.2, §13, §17 | Un olvido de `--replica` reabre el path de mayor riesgo. `default_mode: Replica` en `ResolvedProfile` resuelve esto a nivel de tipo. Opt-out explícito con `--direct`. |
| Removido lenguaje de approvals del resumen y sección empresa | §Resumen, §2 | El alpha registra qué se permitió/bloqueó pero no tiene approval workflow interactivo. Eso es P1. El documento debe prometer solo lo que el alpha demuestra. |
| `SandboxBackend::apply()` reemplazado por `launch()` que devuelve `SandboxedChild` | §12.1 | `apply()` asumía un modelo Linux-centric (fork → apply in-process → exec). En macOS, el path real es exec via `sandbox-exec`. `launch()` deja que cada backend decida su estrategia de lanzamiento sin filtrar suposiciones de plataforma al contrato. |
| Nota de riesgo de timeline añadida al roadmap | §14 | 6 semanas para dual-platform con Landlock, seccomp, Seatbelt/SBPL, CI cross-platform y diffs es un plan con margen estrecho. Semanas 5-6 documentadas como buffer real. SBPL generation + CI macOS identificados como riesgo de integración principal. |

### v3.1 → v3.1.1: Residuos de consistencia

| Cambio | Sección | Razón |
|--------|---------|-------|
| Promesa de red corregida en sección dev Linux | §2 | "No puede conectarse a servidores no autorizados" era falso en el alpha (install usa red `open`). Reescrito para reflejar lo que el alpha sí enforce: filesystem deny + env scrubbing + replica. Filtrado de red por dominio documentado como P1. |
| CLI synopsis restaura `--replica` junto a `--direct` | §3 | `--replica` desapareció del synopsis al añadir `--direct`, pero sigue siendo necesario para perfiles que defaultan a Direct (e.g., `--replica --profile build`). Ahora la interfaz documenta `[--replica | --direct]` con explicación de cuándo usar cada uno. |
| `DefaultMode` separado de `WorkspaceMode` | §12.2 | `ResolvedProfile.default_mode` era `WorkspaceMode` (que lleva `source` y `copy` paths), pero esos paths no existen al resolver un perfil — solo al construir un `ExecutionPlan`. Separar `DefaultMode { Direct, Replica }` (intención) de `WorkspaceMode` (materializado) elimina la mezcla de policy con estado de runtime. |

---

*ClawCrate v3.1.1 — Ejecución segura para agentes AI. El documento promete lo que el alpha puede demostrar. Cada claim tiene enforcement, cada tipo modela lo que representa, cada flag existe en la interfaz que lo documenta.*
