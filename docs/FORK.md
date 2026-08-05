# Fork-Konventionen: opensearch-mcp-server-py

> HRworks-Fork des OpenSearch MCP Servers mit OAuth-Support.

## Aktueller Release

| Tag | Datum | Basis | Beschreibung |
|-----|-------|-------|--------------|
| `v0.11.0-hrw1` | 2026-08-05 | 0.11.0 | OAuth-Integration (Upstream PR #227 + erweiterte Tests) |

## Upstream

- **Repository:** https://github.com/opensearch-project/opensearch-mcp-server-py
- **Fork-Datum:** 2026-08-03
- **Basis-Version:** 0.11.0 (Commit `c53b15d`)

## Branch-Schema

| Branch | Zweck | Beschreibung |
|--------|-------|--------------|
| `main` | **Upstream-Mirror** | Exakte Kopie von `upstream/main`, keine eigenen Commits |
| `fork-main` | **Unser Release-Stand** | Enthält alle HRworks-Patches |
| `feature/*` | Arbeitsbranches | Für einzelne Features/Fixes |

### Warum diese Trennung?

1. **Sauberer Upstream-Sync:** `main` bleibt immer identisch mit Upstream. `git diff upstream/main main` ist immer leer.

2. **Klare Patch-Basis:** `git log main..fork-main` zeigt alle unsere Änderungen.

3. **Einfaches Rebase:** Bei Upstream-Updates rebasen wir `fork-main` auf den neuen `main`.

## Tag-Schema

```
v<upstream-version>-hrw<n>
```

**Beispiele:**
- `v0.11.0-hrw1` — Erster HRworks-Release auf Basis von Upstream 0.11.0
- `v0.11.0-hrw2` — Zweiter Release (z.B. Bugfix)
- `v0.12.0-hrw1` — Erster Release nach Upstream-Upgrade auf 0.12.0

## Sync-Regeln

### Upstream → Fork synchronisieren

```bash
# 1. Upstream fetchen
git fetch upstream

# 2. main auf Upstream aktualisieren
git checkout main
git reset --hard upstream/main
git push origin main

# 3. fork-main rebasen
git checkout fork-main
git rebase main
# Konflikte lösen falls nötig
git push --force-with-lease origin fork-main
```

### Wann synchronisieren?

- **Security-Updates:** Sofort
- **Minor Releases:** Innerhalb 1 Woche evaluieren
- **Major Releases:** Evaluieren, Breaking Changes analysieren

## Exit-Kriterium

Dieser Fork kann aufgelöst werden, wenn:

1. PR #227 (OAuth) upstream gemergt wird, ODER
2. Eine alternative OAuth-Lösung upstream verfügbar ist

Bei Fork-Auflösung:
- Auf Upstream-Release mit OAuth wechseln
- Fork archivieren (nicht löschen — für Historie)

## CI-Status

| Workflow | Status im Fork | Begründung |
|----------|---------------|------------|
| `ci.yml` | ✅ Aktiv | Repo-Check entfernt, Integration-Tests deaktiviert (fehlende Secrets) |
| `changelog.yml` | ✅ Aktiv | Nützlich für PR-Hygiene |
| `publish-release.yml` | ❌ Deaktiviert | Kein PyPI-Publish aus Fork |
| `add-untriaged.yml` | ❌ Deaktiviert | OpenSearch-spezifische Issue-Triage |

## Maintainer

- DevOps-Team, HRworks
