# ClawCrate Development Workflow

Este es el workflow operativo del repo para ejecutar backlog por issue sin perder trazabilidad.

## 1. Sincronizar antes de empezar

Desde `main`:

```bash
git fetch --all --prune
git switch main
git pull --ff-only
git status -sb
```

Comprobar que `main` y `origin/main` apunten al mismo commit:

```bash
git rev-parse main origin/main
```

## 2. Elegir el siguiente issue del backlog

- Fuente de verdad: `docs/backlog.yaml`
- Issues en GitHub se ejecutan en orden del milestone actual.
- Ejemplo de secuencia: `M1-04 -> M1-05 -> M1-06`

## 3. Crear rama por issue

Formato de rama:

```text
issue/mX-YY-descripcion-corta
```

Ejemplo:

```bash
git switch -c issue/m1-04-stack-auto-detection
```

## 4. Implementar solo el scope del issue

- Evitar mezclar cambios no relacionados.
- Mantener commits pequenos y alineados al backlog.

## 5. Validar localmente antes de commit

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## 6. Commit con convencion

Formato recomendado:

```text
<tipo>(mX-YY): <mensaje corto>
```

Ejemplos:

- `feat(m1-04): implement stack auto-detection with safe fallback`
- `test(m1-02): add serde roundtrip tests for core types`
- `ci(m0-02): add baseline workflow for fmt clippy test check`

## 7. Push y Pull Request

```bash
git push -u origin issue/m1-04-stack-auto-detection
gh pr create --base main --head issue/m1-04-stack-auto-detection
```

Reglas del PR:

- Titulo alineado al commit principal.
- Body con resumen corto.
- Incluir cierre automatico del issue:

```text
Closes #<issue-number>
```

Tambien valido: `Fixes #...` o `Resolves #...`.

## 8. Cierre de issues

### Automatico (recomendado)

- Si el PR contiene `Closes/Fixes/Resolves #N`, GitHub cierra el issue al merge en `main`.

### Manual (si aplica)

```bash
gh issue close <issue-number> --repo manuelpenazuniga/ClawCrate --comment "Done via PR #<pr-number>."
```

Cerrar un epic solo cuando todos sus child issues esten cerrados.

## 9. Merge y post-merge

Despues de mergear:

```bash
git switch main
git fetch --all --prune
git pull --ff-only
git status -sb
```

Confirmar:

- `main` sincronizado con `origin/main`
- Issue cerrado en GitHub
- Milestone actualizado correctamente

## 10. Higiene de cambios

- No commitear logs temporales ni archivos locales.
- Si aparecen archivos locales recurrentes, agregarlos a `.gitignore`.
- Mantener cada PR enfocado en un unico issue de backlog.
