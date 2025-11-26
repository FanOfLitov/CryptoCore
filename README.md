# CryptoCore

A command-line file encryption tool implementing AES-128 in multiple modes with secure random key generation.

## Features
- **AES-128** encryption in multiple modes: ECB, CBC, CFB, OFB, CTR
- **Secure random key generation** using cryptographically secure PRNG
- **PKCS#7 padding** for block cipher modes
- **Interoperability** with OpenSSL

## Security
- Uses `os.urandom()` for cryptographically secure random number generation
- Keys and IVs are generated using operating system's CSPRNG
- Weak key detection with warnings for insecure patterns

## Build Instructions

```bash
pip install -r requirements.txt