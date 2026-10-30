# Security policy

BoltShell handles SSH keys, passwords and Passbolt private keys. Please report vulnerabilities privately:

- Use GitHub's **Report a vulnerability** button on the repository's *Security* tab (private advisory), or
- e-mail the maintainers at the address listed on the organisation profile.

Please do not open public issues for security problems. We aim to acknowledge reports within a few working days.

## Design notes

- Secrets are decrypted only when a connection is opened and are never written to disk; the Passbolt private key is
  stored passphrase-protected, as exported by Passbolt.
- Host identities can be pinned in Passbolt (`ssh_host_key`, `rdp_cert_sha256`); otherwise trust on first use.
- The RDP proxy listens on 127.0.0.1 only, with a random per-session token, and is bound to one destination per session.
- Logs (`<config>/logs`) contain diagnostics only, never passwords or keys.

## Audits

**2026-10-30 – security and license audit of commit `7e7742a`** (five findings, all fixed in the following release):

| ID | Finding | Fix |
|---|---|---|
| SEC-01 (high) | Unbound OpenPGP subkeys bypassed the server key pin | Subkeys are used only with a valid binding signature from the pinned primary key; signing subkeys also need a valid back-signature; revocation, expiry and key flags come from verified signatures (`Crypto/PgpKeyValidation.cs`) |
| SEC-02 (high) | Remote file names like `..\x` could leave the download folder on Windows | Remote names are validated as single file names, the full path is checked to stay inside the target folder, and nothing is written through existing links (`Transfer/LocalPaths.cs`) |
| LIC-01 (medium) | License texts missing from distributed packages | GPL, `THIRD_PARTY_NOTICES.md` and full texts in `licenses/` ship with every build; CI fails if any is missing |
| SEC-03 (medium) | Account-kit import accepted `http://` servers | HTTPS is enforced centrally in the API client, on import and when adding accounts (loopback excepted) |
| SEC-04 (medium) | Locked accounts still allowed new connections from open tabs | Locking drops cached credentials; duplicate, reconnect and SFTP require unlocking and fresh decryption |
