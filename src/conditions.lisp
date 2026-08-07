(in-package #:secrets-protocol)

(define-condition secrets-error (error)
  ((message :initarg :message :reader secrets-error-message :initform nil))
  (:report (lambda (c s)
             (format s "secrets error~@[: ~a~]" (secrets-error-message c)))))

(define-condition secrets-verify-error (secrets-error) ())
