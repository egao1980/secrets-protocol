# secrets-protocol

Lispy **CLOS** secrets API for [cl-stack](https://github.com/egao1980/cl-stack) — CSPRNG, tokens, constant-time compare, UUID, password KDFs.

| System | Role | Repo |
|--------|------|------|
| `secrets-protocol` (`stack-secrets`) | Protocol / API | this repo |
| `crypto-backend-ironclad` | Default backend (Ironclad CSPRNG + uuid + Argon2i/PBKDF2) | [`egao1980/crypto-backend-ironclad`](https://github.com/egao1980/crypto-backend-ironclad) |

Digests/AEAD live in [`crypto-protocol`](https://github.com/egao1980/crypto-protocol). The Ironclad backend implements **both** protocols in one system — there is no separate `secrets-backend-os`.

```lisp
(asdf:load-system "crypto-backend-ironclad")
;; binds *secrets-backend* and *crypto-backend*

(stack-secrets:token-hex 32)
(stack-secrets:token-urlsafe 32)
(stack-secrets:uuid :version :v4)

(let ((h (stack-secrets:hash-password "s3cret")))
  (stack-secrets:verify-password "s3cret" h))
```

## License

MIT
