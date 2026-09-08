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
| `cli-crash.campaign.json` | Hostile stdin crash | `parse.py` + NUL |
| `lib-call-twice.campaign.json` | Consume-once replay | `once.py` invoked twice |

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
