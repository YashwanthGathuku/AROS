# HTTP/API class campaigns

Reusable red-team classes. Point `--target` at **any** local HTTP tree
that speaks the bind parameters. Nothing is written into that tree.

| Campaign | Class | Default bind |
|---|---|---|
| `http-idor.campaign.json` | Broken object-level authorization | `GET /users/2` as `user=1`, needle `bob-secret` |
| `http-path-traversal.campaign.json` | CWE-22 path escape | `GET /files?path=../secret.txt`, needle `fixture-path-secret` |
| `http-surface-map.campaign.json` | Recon | source paths + live GET wordlist |

Override `generator.bind` in a copy (or a future overlay) when the target
uses different URLs. Do not fork the target to add a harness.

```text
aros campaign run --spec campaign-loader/classes/http-idor.campaign.json --target path/to/app
```
