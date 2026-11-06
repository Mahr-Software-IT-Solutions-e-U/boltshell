# Code signing

## macOS (Developer ID + notarization)

The `build` workflow signs and notarizes the macOS packages (`.app` inside the portable zip and the `.pkg` installer)
with Velopack when the secrets below exist. Pull requests and forks build unsigned, as before.

### One-time setup (Apple Developer account, role *Account Holder* for Developer ID certificates)

1. **Certificates** – developer.apple.com → Certificates, IDs & Profiles → Certificates → **+**:
   - *Developer ID Application*
   - *Developer ID Installer*

   Each needs a certificate signing request (on a Mac: Keychain Access → Certificate Assistant →
   *Request a Certificate From a Certificate Authority* → saved to disk). Download both certificates and double-click
   them so they land in the login keychain next to their private keys.
2. **Export** – in Keychain Access select *both* certificates (with their private keys) → *Export 2 items…* →
   `certificates.p12` with a strong password.
   **Without a Mac** (Windows: *Git Bash* from Git for Windows, or Linux/WSL) – one private key and one signing
   request are used for both certificates, so a single `.p12` holds both identities:

   ```bash
   openssl req -new -newkey rsa:2048 -nodes -keyout developer-id.key -out developer-id.csr \
     -subj "/emailAddress=you@example.com/CN=Your Name/C=AT"
   # upload developer-id.csr for "Developer ID Application" and again for "Developer ID Installer",
   # download developerID_application.cer and developerID_installer.cer
   curl -sO https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
   openssl x509 -inform DER -in developerID_application.cer -out application.pem
   openssl x509 -inform DER -in developerID_installer.cer -out installer.pem
   openssl x509 -inform DER -in DeveloperIDG2CA.cer -out intermediate.pem
   cat installer.pem intermediate.pem > extra.pem
   openssl pkcs12 -export -inkey developer-id.key -in application.pem -certfile extra.pem -name "Developer ID" \
     -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -out certificates.p12
   ```

   The SHA1/3DES options produce a `.p12` that macOS' `security import` reads on every version. Keep
   `developer-id.key` (or the `.p12`) somewhere safe, e.g. in Passbolt, and delete the loose files.
3. **Notarization key** – App Store Connect → Users and Access → Integrations → App Store Connect API →
   Team Keys → **+** (access: *Developer*). Download the `.p8` (only possible once) and note *Key ID* and *Issuer ID*.
4. **GitHub secrets** – repository → Settings → Secrets and variables → Actions → *New repository secret*:

   | Secret | Value |
   |---|---|
   | `MACOS_CERTIFICATES_P12` | `base64 -i certificates.p12` (Linux/Git Bash: `base64 -w0 certificates.p12`) |
   | `MACOS_CERTIFICATES_PASSWORD` | password of the `.p12` |
   | `APPLE_API_KEY_P8` | `base64 -i AuthKey_XXXXXXXXXX.p8` (Linux/Git Bash: `base64 -w0 …`) |
   | `APPLE_API_KEY_ID` | Key ID |
   | `APPLE_API_ISSUER_ID` | Issuer ID |

   Never put these values into issues, chats or the repository.

### What the workflow does

- Imports the `.p12` into a temporary keychain, finds the *Developer ID Application/Installer* identities and stores
  the API key as notarytool profile `boltshell` there.
- `vpk pack --signAppIdentity … --signInstallIdentity … --signEntitlements build/macos/entitlements.plist
  --notaryProfile boltshell --keychain …` signs with the hardened runtime, notarizes and packages.
- Checks the installer with `pkgutil --check-signature` and `spctl`, then deletes the keychain.

`build/macos/entitlements.plist` contains the hardened-runtime exceptions the .NET runtime needs (JIT, unsigned
executable memory, library validation off for the bundled native libraries).

## Windows

Not set up yet. Options: Azure Trusted Signing (`vpk pack --azureTrustedSignFile`), SignPath Foundation (free for open
source, signs as "SignPath Foundation"), or a classic certificate via `--signParams` (signtool).
