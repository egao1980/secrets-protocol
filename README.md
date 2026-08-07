# secrets-protocol

CLOS secrets API for [cl-stack](https://github.com/egao1980/cl-stack) — CSPRNG, tokens, constant-time compare, UUID, password KDFs.

**Protocol only.** Default backend is Ironclad via [`crypto-backend-ironclad`](https://github.com/egao1980/crypto-backend-ironclad) (same system as crypto).

```lisp
(asdf:load-system "crypto-backend-ironclad")  ; binds *secrets-backend* + *crypto-backend*
(stack-secrets:token-urlsafe 32)
(stack-secrets:hash-password "s3cret")
```

Package nick: `stack-secrets`. Digests/AEAD → [`crypto-protocol`](https://github.com/egao1980/crypto-protocol).

## License

MIT
