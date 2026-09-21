(defpackage #:secrets-protocol
  (:use #:cl)
  (:nicknames #:stack-secrets)
  (:export #:secrets-error
           #:secrets-error-message
           #:secrets-verify-error

           #:secrets-backend
           #:*secrets-backend*

           #:backend-random-bytes
           #:backend-uuid
           #:backend-password-hash
           #:backend-password-verify

           #:random-bytes
           #:token-bytes
           #:token-hex
           #:token-urlsafe
           #:constant-time-equal
           #:uuid
           #:make-uuid-v7
           #:hash-password
           #:verify-password

           #:secret-ref
           #:secret-ref-p
           #:make-secret-ref
           #:secret-ref-name
           #:secret-ref-key
           #:secret-ref-inject

           #:secret-store
           #:secret-store-p
           #:resolve-secret
           #:put-secret

           #:in-memory-secret-store
           #:in-memory-secret-store-p
           #:make-in-memory-secret-store))

(in-package #:secrets-protocol)
