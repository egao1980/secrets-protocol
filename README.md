# secrets-protocol

Lispy **CLOS** secrets for [cl-stack](https://github.com/egao1980/cl-stack) — CSPRNG, tokens, constant-time compare, UUID, password KDFs.

| System | Role |
|--------|------|
| `secrets-protocol` (`stack-secrets`) | API |
| `secrets-backend-os` | OS CSPRNG via Ironclad + uuid |

Shape: Python `secrets` + Java `SecureRandom` + Argon2/PBKDF2. Digests/AEAD live in [`crypto-protocol`](https://github.com/egao1980/crypto-protocol).

```lisp
(asdf:load-system "secrets-backend-os")

(stack-secrets:token-hex 32)
(stack-secrets:token-urlsafe 32)
(stack-secrets:uuid :version :v4)

(let ((h (stack-secrets:hash-password "s3cret")))
  (stack-secrets:verify-password "s3cret" h))
```

## License

MIT
