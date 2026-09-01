# Mislabelled fixture

This directory is labelled **vulnerable** and is run as `FixtureKind::Authz`.
`server.py` is the patched authorization implementation (`VULN_IDOR = False`).

AROS must refuse to verify a finding. A pipeline that trusts the directory
label instead of the observed HTTP oracle will incorrectly promote this to E3+.
