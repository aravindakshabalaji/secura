# Secura: Modern Cryptographic Tools Suite

Secura is a cross-platform cryptographic suite providing **AES**, **RSA**, **Diffie-Hellman**, **Hashing**, and **Key Management** utilities through a clean, modern UI. It is designed for learning and experimentation with cryptographic primitives.

Secura is powered by [pycrypt](https://pypi.org/project/pycrypt-lib/).

---

## Features

### **User Accounts & Personal Key Storage**

- Local SQLite-backed user system with securely stored passwords.
- Secure per-user encrypted-at-rest storage for AES, RSA, and DH key materials.

### **Modular Cryptographic Suite**

- **AES Encrypt / Decrypt**
  - ECB, CBC, CTR, GCM modes
  - Text-mode and file-mode encryption

- **RSA Operations**
  - Encrypt / Decrypt, Sign / Verify text and file data

- **Diffie-Hellman Key Exchange**
  - HKDF key derivation from Diffe-Hellman exchange
- **Hashing Utilities**
  - SHA1, SHA256 modes
  - Hashing for text and file data
  - Hash based functions (HMAC, HKDF)

- **Key Management**
  - Key generation, secure storage for AES, RSA, and DH

### **Modern UI / UX**

- Uniform Material-3 themed light/dark mode with custom design
- Haptic feedback support, animated UI, responsive layout.

## Installation & Running

Secura runs as **desktop**, **mobile**, or a **web** app using Flet.

### Option 1: Download pre-built binaries

You can download signed, pre-built binaries from the [GitHub Releases](https://github.com/aravindakshabalaji/secura/releases) page:

- Windows — .msi installer
- macOS — .dmg bundle
- Android — .apk package

> ⚠️ **Note:**
> Only a portable build is available for Linux

### Option 2: Run from source

#### Using `uv`

Desktop:

```bash
uv run flet run
```

Web:

```bash
uv run flet run --web
```

#### Using `poetry`

Install dependencies:

```bash
poetry install
```

Desktop:

```bash
poetry run flet run
```

Web:

```bash
poetry run flet run --web
```

## Build Targets

### Windows / Linux / macOS

```bash
flet build windows -v
# or
flet build linux -v
# or
flet build macos -v
```

### Mobile

```bash
flet build apk -v      # Android
flet build ipa -v      # iOS
```

---

## Security Notes

- This software is for **education and experimentation** only.
- It should **not** be used for production-grade security systems.


## License

Secura is licensed under the **GNU GPL-3.0-or-later**.

See [LICENSE](LICENSE) for the full text.
