# RouteLint

A doctor for [Mihomo](https://github.com/MetaCubeX/mihomo) / Clash.Meta `config.yaml` files.

It does **not** replace `mihomo -t` — it complements it with three layers:

| Layer | What it does | Requirements |
|---|---|---|
| **schema** | validates the config against a JSON Schema | `--schema path` + `pip install 'routelint[schema]'` |
| **native** | runs `mihomo -t` and surfaces its verdict | `mihomo` in `PATH` (or `--mihomo`) |
| **semantic** | lints for operational problems that neither of the above can see | always on |

The semantic layer finds real-world config bugs: dangling proxy/group/provider references, circular groups, unreachable rules after `MATCH`, an exposed `external-controller` without a secret, `external-ui` misconfiguration, DNS leak risks (TUN without DNS), and common routing anti-patterns (`GEOIP,CN` via proxy, broad IP rules shadowing domain rules, `MATCH,REJECT`, ...).

RouteLint is an independent tool and is not affiliated with the Mihomo / Clash.Meta projects; their binaries are invoked via the local `PATH` only when requested.

## Install

```bash
pip install routelint              # runtime: PyYAML only
pip install 'routelint[schema]'    # + jsonschema for the schema layer
```

Requires Python 3.10+.

## Usage

```bash
routelint config.yaml
routelint config.yaml --format json
routelint config.yaml --schema mihomo_schema.json
routelint config.yaml --mihomo /usr/bin/mihomo
routelint config.yaml --disable SEC,UNUSED --only ""   # rule filtering
routelint config.yaml --min-severity warn
```

Missing layers degrade gracefully: no `--schema` → schema layer is `skipped`; no `mihomo` binary → native layer is `skipped`.

### Severities

- `info` — worth knowing (unused proxy, no explicit `MATCH`)
- `warn` — likely a mistake (duplicate rules, open DNS listener, `GEOIP,CN` via proxy)
- `error` — config is broken or rules are unreachable
- `high` — security/leak risk (exposed API without secret, TUN without DNS)

### Exit codes

- `0` — no findings at/above the error threshold
- `1` — findings at `error`/`high` severity (or the config could not be parsed)
- `2` — usage error

## Example

```text
routelint report: config.yaml

Layers:
  [+] schema     skipped  no --schema given
  [+] native     ok  mihomo -t passed
  [-] semantic   failed  15/15 rules applied

Findings (3): 1 high, 1 error, 1 warn

  [HIGH ] SEC001  external-controller exposed without secret
          path: external-controller
          external-controller '0.0.0.0:9090' listens on all interfaces with no `secret` set
          hint: anyone on the network can read traffic and reconfigure the proxy; set a secret or bind to 127.0.0.1
  ...
```

## Rule codes

| Prefix | Area |
|---|---|
| `SCHEMA`, `NATIVE`, `CONFIG` | layer-level failures |
| `REF`, `RULE`, `DUP`, `UNUSED` | reference integrity |
| `CYC` | group cycles |
| `SHD`, `DUPRULE` | rule shadowing / duplicates |
| `SEC`, `UI` | control-plane security |
| `DNS`, `DNSLISTEN`, `DNSSAN` | DNS sanity and leaks |
| `RT`, `RTGEO`, `RTORD` | routing anti-patterns |

## Architecture

```
loader.py            YAML -> dict + Ctx (indexes of proxies/groups/providers)
schema_validator.py  layer 1 (optional jsonschema)
native_validator.py  layer 2 (subprocess adapter around `mihomo -t`)
engine.py            layer 3 (applies rules)
rules/               semantic rules: one class, one check(ctx) -> [Finding]
reporters/           text / json renderers
cli.py               argparse CLI, exit codes
```

Adding a rule = one class in `rules/` with a `check()` method plus a registration line. Reporters and layers are independent, so a future web UI can call `run_*_layer` + `report.as_dict()` directly.

## Development

```bash
uv venv && uv pip install -e '.[dev]' --python .venv
pytest
```

## License

MIT
