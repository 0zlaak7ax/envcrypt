# envcrypt

Lightweight utility to encrypt and version-control `.env` files using [age](https://github.com/FiloSottile/age) encryption with team key management.

---

## Installation

```bash
go install github.com/yourusername/envcrypt@latest
```

Or download a prebuilt binary from the [releases page](https://github.com/yourusername/envcrypt/releases).

---

## Usage

**Encrypt a `.env` file before committing:**

```bash
envcrypt encrypt --in .env --out .env.age --keys team-keys.txt
```

**Decrypt on another machine:**

```bash
envcrypt decrypt --in .env.age --out .env --identity ~/.age/key.txt
```

**Add a new team member's public key:**

```bash
envcrypt keys add --file team-keys.txt --key "age1ql3z7hjy..."
```

Commit `.env.age` and `team-keys.txt` to version control. Keep `.env` in `.gitignore`.

```gitignore
.env
!.env.age
```

---

## How It Works

1. Each team member generates an age key pair (`age-keygen`)
2. Public keys are stored in `team-keys.txt` and committed to the repo
3. `.env` files are encrypted against all team public keys
4. Any team member with a matching private key can decrypt locally

---

## Requirements

- Go 1.21+
- [age](https://github.com/FiloSottile/age) (`brew install age` or `apt install age`)

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss any significant changes.

---

## License

[MIT](LICENSE)