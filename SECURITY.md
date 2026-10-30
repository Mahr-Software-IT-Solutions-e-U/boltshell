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
