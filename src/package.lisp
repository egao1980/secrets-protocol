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
           #:hash-password
           #:verify-password))

(in-package #:secrets-protocol)
