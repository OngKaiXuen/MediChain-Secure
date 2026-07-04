# MediChain E-MedicVault — Secure Refactor

Post-incident hardened refactor of the compromised MediChain *E-MedicVault* artifacts for
**SECR4483/SCSR4483 Secure Programming — Alternative Assessment**.

| Legacy file | Primary flaws | Remediation in this repo |
|---|---|---|
| `search.php` | SQL Injection (A), Reflected XSS (B/C) | PDO prepared statements + `htmlspecialchars()` context-aware output encoding |
| `auth.php` | Byte-length bound check (D), MD5 hashing (E) | `mb_strlen()` semantic check + Argon2id (`password_hash`/`password_verify`) |
| `crypto_vault.php` | AES-128-ECB pattern leakage (F), hardcoded key (G) | AES-256-GCM AEAD, 12-byte IV, `.env`-decoupled key, exception-trapped tag mismatch |

## Layout

```
src/
  db_config.php      # hardened PDO bootstrap (least-privilege, .env-driven)
  search.php         # refactored — SQLi + XSS fixed
  auth.php           # refactored — bound + hashing fixed
  crypto_vault.php   # CryptoVault class — AES-256-GCM AEAD
tests/
  CryptoVaultTest.php
schema.sql           # migrated schema (Argon2id credential column)
.env.example         # safe template (.env itself is git-ignored)
composer.json / phpunit.xml
```

## Setup (Windows)

Requires **PHP 8.1+** with the `openssl` and `mbstring` extensions enabled, plus Composer.
Run the following in **PowerShell**:

```powershell
composer install                      # skip if vendor/ is already present
Copy-Item .env.example .env           # then edit .env with real secrets
Get-Content schema.sql | mysql -u root -p   # optional: only needed to run search/auth against a DB
```

Generate a strong master key:

```powershell
php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
```

## Run the test suite

```powershell
php vendor/bin/phpunit --testdox
```

Expected: **OK (5 tests)** — an untampered encrypt/decrypt lifecycle, non-deterministic
ciphertext (no ECB leakage), a tampered payload trapped as a thrown AEAD exception, a
truncated-payload rejection, and Argon2id credential integrity.

## Demo credentials (lab only)

`schema.sql` seeds Argon2id-hashed accounts: `dr_faizal` / `testkey123`,
`dr_sharifah` / `doctorsecret`.

> Security note: `.env` is git-ignored; only `.env.example` is committed. Never commit real secrets.
