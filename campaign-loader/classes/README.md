# HTTP/API class campaigns

Reusable red-team classes. Point `--target` at **any** local HTTP tree
that speaks the bind parameters. Nothing is written into that tree.

| Campaign | Class | Default bind |
|---|---|---|
| `http-idor.campaign.json` | Broken object-level authorization | `GET /users/2` as `user=1`, needle `bob-secret` |
| `http-unauth.campaign.json` | Missing session | `GET /users/2` with no cookie |
| `http-cookie-confusion.campaign.json` | Client-chosen identity cookie | `Cookie: user=1; user=2` on `/users/2` |
| `http-path-traversal.campaign.json` | CWE-22 path escape | `GET /files?path=../secret.txt` |
| `http-surface-map.campaign.json` | Recon | source paths + live GET wordlist |
| `http-mr-cookie-drop.campaign.json` | MST-wi: drop session cookie | `/users/2` with vs without Cookie |
| `http-mr-method.campaign.json` | MST-wi: GET vs POST | same path, method change |
| `http-mr-cross-user.campaign.json` | MST-wi: low-priv vs owner | `user=1` must not see `bob-secret` |
| `http-mr-header-noise.campaign.json` | MST-wi: extra header must not grant | `X-Role: admin` gain check |
| `http-mr-query-noise.campaign.json` | MST-wi: extra query must not grant | `?role=admin` gain check |
| `http-mr-encoded-dotdot.campaign.json` | MST-wi: encoded `../` | `/files?path=..%2Fsecret.txt` |
| `http-mr-dot-segment.campaign.json` | MST-wi: `./../` | `/files?path=./../secret.txt` |
| `http-mr-encoded-dot.campaign.json` | MST-wi: `%2e%2e%2f` | `/files?path=%2e%2e%2fsecret.txt` |
| `http-mr-xff.campaign.json` | MST-wi: forwarded-user must not grant | `X-Forwarded-User: 2` |
| `cli-crash.campaign.json` | Hostile stdin crash | `parse.py` + NUL |
| `lib-call-twice.campaign.json` | Consume-once replay | `once.py` invoked twice |
| `mutate-fuzz.campaign.json` | Mutational fuzz + shrink; AFL++/libFuzzer when present | `parse.py` or `bind.binary` |
| `klee-run.campaign.json` | KLEE fail-closed | bound bitcode or hold |
| `prop-ascii.campaign.json` | QuickCheck: no crash on printable ASCII | `parse.py`, deterministic seed |

```text
aros campaign map --target path/to/app --out data/work/surface.json
aros campaign gate --target path/to/app --pack http
```

`gate` fails if any class is Verified (do not ship) or if containment cannot be shown.

Override `generator.bind` in a copy (or a future overlay) when the target
uses different URLs. Do not fork the target to add a harness.

```text
aros campaign run --spec campaign-loader/classes/http-idor.campaign.json --target path/to/app
```
