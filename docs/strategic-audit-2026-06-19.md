# ClawCrate - Status Audit 2026-06-19

**Fecha del reporte:** 2026-06-19
**Branch revisado:** `main` @ `b2985d1` (`origin/main` sincronizado).
**Release publico mas reciente:** `v0.1.0-alpha.2`, publicado 2026-04-30.
**Referencia requerida:** `docs/status-2026-05-09.md`.

Este reporte actualiza el corte del 2026-05-09 y separa tres preguntas:

1. Que avanzo desde el ultimo status.
2. Que riesgos bloquean o condicionan el siguiente release.
3. Cual es la direccion ejecutable para retomar avance.

## TL;DR

- El reporte del 2026-05-09 ya quedo desactualizado en el lado positivo: entre 2026-05-13 y 2026-05-15 se cerraron los pendientes T0, el Compliance Kit, benchmarks de hash chain y perfiles MCP base.
- El proyecto volvio a detenerse despues del 2026-05-15. Al 2026-06-19 no hay PRs abiertos y el ultimo release publicado sigue siendo `v0.1.0-alpha.2` del 2026-04-30.
- La suite local esta verde: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` y `cargo test --workspace` pasan.
- Smoke macOS fuera del sandbox de Codex: `clawcrate run --profile safe -- /bin/echo ok` pasa; acceso a `~/.ssh` bajo `safe` falla; `CLAWCRATE_AUDIT_HASHCHAIN=1` produce una cadena verificable con `clawcrate verify`.
- El proximo corte recomendado es `v0.2.0-alpha.0` como release de Compliance Kit + perfiles MCP base. El hardening previo al corte debe mantener cubiertos dos puntos: no filtrar variables internas de audit signing hacia el child y no sobreprometer enforcement Linux/filtered network en docs.
- El roadmap vivo ya no es "hacer hash chain"; eso esta cerrado. El cuello de botella actual es el MCP Server Firewall: issues #253-#259.

## Delta vs 2026-05-09

El status del 09-05 decia que el producto habia publicado alpha.2 y se habia detenido. Eso fue cierto hasta el 13-05, pero luego hubo una rafaga de cierre:

| Area | Estado 09-05 | Estado 19-06 |
| --- | --- | --- |
| Docs no commiteados | Pendientes | Cerrado via PR #236 |
| CHANGELOG alpha.2 | Pendiente | Cerrado via PR #237 |
| Agent demo | No existia | `examples/agent-demo/` existe via PR #238 |
| `agent-inference-allowlist` | Pendiente | Existe via PR #239 |
| Hash chain audit | Pendiente | Cerrado via PR #241 |
| Canonical JSON | Pendiente | Cerrado via PR #242 |
| `clawcrate verify` | Pendiente | Cerrado via PR #243 |
| Ed25519 block signing | Pendiente | Cerrado via PR #244 |
| SIEM audit export | Pendiente | Cerrado via PR #245 |
| EU AI Act docs | Pendiente | Cerrado via PR #246 |
| IETF audit trail docs | Pendiente | Cerrado via PR #247 |
| Hash chain bench | Pendiente | Cerrado via PR #248 |
| MCP profiles base | Pendiente | `mcp-server` y `mcp-readonly` cerrados via PR #250/#252 |

La lectura honesta: se recupero mucho trabajo entre 13-05 y 15-05, pero despues hubo otra pausa larga. El problema actual no es falta de plan; es reactivar ejecucion.

## Roadmap Vivo

La fuente estructurada actual es `docs/backlog.yaml`; la guia operacional vigente es `docs/planning-2026-05-15.md`.

Issues abiertos en GitHub al 2026-06-19:

| Issue | Milestone | Prioridad | Estado |
| ---: | --- | --- | --- |
| #219 | `v0.2.0` | p0 | Epic MCP Server Firewall |
| #253 | `v0.2.0` | p0 | `clawcrate mcp wrap` subcommand |
| #254 | `v0.2.0` | p0 | Relay stdin/stdout transparente para JSON-RPC |
| #255 | `v0.2.0` | p0 | Auto-detect MCP server shape |
| #256 | `v0.2.0` | p0 | Claude Desktop MCP wrap recipe |
| #257 | `v0.2.0` | p0 | Cursor MCP wrap recipe |
| #258 | `v0.2.0` | p0 | Continue.dev MCP wrap recipe |
| #259 | `v0.2.0` | p0 | Demo `@modelcontextprotocol/server-filesystem` |
| #220 | `v0.3.0` | p1 | Distribution: GitHub Action, integrations, VS Code |
| #221 | `v0.3.0` | p1 | `profiles.dev` marketplace |
| #222 | `v0.4.0` | p1 | `clawcrate learn` auto-policy |

Conclusion de roadmap: `v0.2.0` debe terminar MCP Server Firewall. `v0.3.0` debe enfocarse en adopcion/distribucion. `v0.4.0` queda como leap feature.

## Auditoria de Seguridad

### Fortalezas

- macOS tiene enforcement real con Seatbelt y smoke local exitoso.
- `install` y perfiles MCP nuevos usan Replica por defecto, alineado con la limitacion documentada de Linux sobre denies intra-workspace.
- Env scrub existe y cubre patrones comunes: `AWS_*`, tokens, passwords, keys, `SSH_AUTH_SOCK`, `DATABASE_URL`.
- Auditabilidad subio de nivel: hash chain SHA-256 opt-in, canonical JSON, `verify`, Ed25519 block signatures y export SIEM.
- API local exige bearer token, usa comparacion constante y tiene cola acotada para rutas delegadas.

### Riesgos p0/p1

1. **Variables internas de audit signing hacia el proceso sandboxed.**
   Riesgo identificado: `scrub_environment` conservaba variables que no matcheaban `env_scrub`; los perfiles no eliminaban `CLAWCRATE_AUDIT_SIGN`. Un comando podia ver el path de la private key usada para firmar audit blocks si el operador la exponia via env. Mitigacion aplicada en el working tree: `CLAWCRATE_AUDIT_*` se elimina siempre del entorno del child, incluso si un perfil intenta pasarlo con `CLAWCRATE_*`.

2. **Linux Landlock parece proteger escritura, no lectura.**
   El backend Linux construye el ruleset con `LANDLOCK_ACCESS_FS_BASE_WRITE` y agrega fds solo desde `fs_write`. Eso valida "no escribir fuera de allowlist", pero no equivale a "solo puede leer workspace". En Linux Direct Mode, no se debe prometer bloqueo de lectura de secretos fuera de Replica Mode. Dos opciones: implementar Landlock read access handling por `fs_read`, o ajustar README/docs/release notes para no sobreprometer.

3. **`network: filtered` es proxy/env-based, no enforcement transparente perfecto.**
   El proxy esta acotado y tiene SNI enforcement para CONNECT, pero los backends permiten red para `Filtered` y dependen de que la herramienta respete `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY`. La documentacion debe decir "filtered best-effort / proxy-mediated" salvo que se garantice loopback-only + bloqueo de egress directo por backend.

4. **Artifacts no fuerzan permisos restrictivos.**
   `ArtifactWriter` usa `create_dir_all` y `OpenOptions` sin `0700/0600`. La seguridad depende de umask. Para logs compliance, crear `~/.clawcrate` y runs con permisos restrictivos deberia ser p1.

5. **API local permite bind arbitrario.**
   El default es `127.0.0.1`, correcto. Si el usuario usa `--bind 0.0.0.0`, queda expuesto con bearer token. Debe haber warning fuerte o rechazo por defecto para non-loopback salvo `--allow-remote-bind`.

## Auditoria de Escalabilidad

- `clawcrate-cli/src/main.rs` tiene 4752 lineas y concentra CLI, API, bridge, replica, audit export, verify y run pipeline. Agregar MCP ahi aumentara riesgo. Recomendacion: extraer modulos `api`, `run_pipeline`, `replica`, `audit_export`, `mcp` antes o durante #253-#254 si el cambio empieza a ensuciar el archivo.
- Replica Mode hace copia recursiva completa. Para monorepos y MCP servers de filesystem puede ser lento. Proxima mejora de alto retorno: hardlinks/copy-on-write donde sea seguro, o replica por allowlist.
- `fs-diff` hashea contenido completo de archivos en roots escribibles antes/despues. Correcto para evidencia, caro para arboles grandes. A futuro conviene modo metadata-first con hash bajo demanda, manteniendo el modo audit-grade actual.
- API usa `tiny_http`, workers fijos y ejecuta el binario actual como subprocess para cada plan/run. Es suficiente para local alpha, no para multi-cliente intensivo. No migrar a Tokio ahora; solo documentar limites y mantener cola acotada.
- Egress proxy usa thread por handler con limite 64. Adecuado para dev local; no vender como proxy de alto throughput.

## Verificacion Local Ejecutada

Comandos:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench -p clawcrate-audit --bench hash_chain -- --sample-size 10
target/debug/clawcrate run --json --profile safe -- /bin/echo ok
target/debug/clawcrate run --json --profile safe -- /bin/ls /Users/mpz/.ssh
CLAWCRATE_AUDIT_HASHCHAIN=1 target/debug/clawcrate run --json --profile safe -- /bin/echo audit-ok
target/debug/clawcrate verify 019ee22c-7059-7c31-a442-7cae42727c21 --json
```

Resultados:

- fmt: OK.
- clippy: OK.
- tests: OK, 170 tests/doc-tests reportados en total.
- macOS doctor: `seatbelt_available=true`, `macos_version=26.5.1`, `kernel_version=25.5.0`.
- safe echo smoke: OK.
- `~/.ssh` smoke bajo `safe`: exit code 1, esperado para bloqueo.
- hash chain verify: `valid=true`, 4 eventos.
- bench reducido:
  - `hash_chain_compute_single_event`: ~2.1-3.3 us.
  - append de evento en archivo nuevo: ~331-357 us.
  - verify de 10k eventos: ~31.3-31.9 ms.

Nota: Criterion marco regresion en los dos primeros benches contra historial local, pero la muestra fue reducida (`sample-size 10`); tomarlo como smoke, no como benchmark oficial.

## Recomendacion de Release

### Opcion recomendada: `v0.2.0-alpha.0` pronto

Scope:

- Compliance Kit: hash chain, canonical JSON, verify, signing, SIEM export.
- Docs de compliance EU AI Act + IETF.
- Bench de hash chain.
- Community profiles nuevos: `agent-inference-allowlist`, `mcp-server`, `mcp-readonly`.
- Agent demo.
- Changelog alpha.2 corregido.

Precondiciones antes de tag:

1. Mantener verde el test que verifica que `CLAWCRATE_AUDIT_*` no llega al child.
2. Confirmar que README/docs no sobreprometen Linux read isolation ni `filtered` network.
3. Bump workspace version a `0.2.0-alpha.0`.
4. Agregar seccion `0.2.0-alpha.0` al CHANGELOG.
5. Ejecutar release gate completo.

Comando de corte esperado:

```bash
bash scripts/cut_release.sh --tag v0.2.0-alpha.0 --push
```

### Despues del release

Retomar `v0.2.0-alpha.1` con MCP Server Firewall:

1. #253 `clawcrate mcp wrap` subcommand.
2. #254 relay stdin/stdout sin romper JSON-RPC.
3. #255 autodeteccion de MCP server.
4. #256-#258 recetas Claude Desktop, Cursor, Continue.dev.
5. #259 demo filesystem MCP.

No conviene esperar a que #253-#259 terminen para publicar el Compliance Kit. Ya hay suficiente valor unreleased en `main`, y el ultimo release publico tiene 50 dias al 2026-06-19.

## Direccion Clara

Prioridad de las proximas dos semanas:

1. **Release `v0.2.0-alpha.0`** con hardening minimo de claims/env internos. Esto desbloquea narrativa publica y reduce el gap entre `main` y releases.
2. **Implementar #253 y #254 juntos o secuenciales muy chicos.** La regla debe ser no imprimir nada protocol-visible en stdout del wrapper, porque stdout pertenece al JSON-RPC del MCP server.
3. **Publicar una demo MCP real (#259)** inmediatamente despues de #254. El valor diferencial no es "otro perfil", es "un MCP server de filesystem queda sandboxed sin que Claude/Cursor/Continue cambien su protocolo".
4. **Mover adopcion a `v0.3.0`.** GitHub Action, VS Code y profiles.dev son importantes, pero no deben distraer del wrapper MCP hasta que exista baseline usable.

Veredicto: ClawCrate esta en mejor estado tecnico que el reporte del 09-05, pero peor en ritmo. El repo tiene valor suficiente para release, y el proximo bloque tiene un objetivo claro: publicar Compliance Kit ahora y terminar MCP Server Firewall como la siguiente historia de producto.
