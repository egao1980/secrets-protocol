# secrets-protocol

Lispy **CLOS** secrets API for [cl-stack](https://github.com/egao1980/cl-stack) — CSPRNG, tokens, constant-time compare, UUID, password KDFs.

| System | Role | Repo |
|--------|------|------|
| `secrets-protocol` (`stack-secrets`) | Protocol / API | this repo |
| `secrets-protocol/store` | `secret-ref` + `resolve-secret` (material never lives on the ref) | this repo |
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

`secrets-protocol/store` adds `secret-ref` (name, key, inject `:env` or `:file`) and `resolve-secret`. Material is never stored on the ref. A missing secret signals `secrets-error` with restart `use-value`. `in-memory-secret-store` is for tests.

```lisp
(asdf:load-system "secrets-protocol/store")
(let* ((store (stack-secrets:make-in-memory-secret-store
               :secrets '(("svc" "api-key" "s3cret"))))
       (ref (stack-secrets:make-secret-ref :name "svc" :key "api-key")))
  (stack-secrets:resolve-secret store ref))
```

Offline demo (journal the ref, not the material):

```bash
sbcl --load examples/store.lisp
```

## License

MIT
