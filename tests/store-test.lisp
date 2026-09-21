(in-package #:secrets-protocol/tests)

(deftest secret-ref-has-no-material-slot
  (let ((ref (secrets-protocol:make-secret-ref :name "vault" :key "token"
                                               :inject :file)))
    (ok (secrets-protocol:secret-ref-p ref))
    (ok (string= "vault" (secrets-protocol:secret-ref-name ref)))
    (ok (string= "token" (secrets-protocol:secret-ref-key ref)))
    (ok (eq :file (secrets-protocol:secret-ref-inject ref)))
    (ng (slot-exists-p ref (intern "MATERIAL" :secrets-protocol)))))

(deftest resolve-secret-hits
  (let* ((store (secrets-protocol:make-in-memory-secret-store
                 :secrets '(("svc" "api-key" "s3cret"))))
         (ref (secrets-protocol:make-secret-ref :name "svc" :key "api-key")))
    (ok (string= "s3cret" (secrets-protocol:resolve-secret store ref)))))

(deftest resolve-secret-missing
  (let ((store (secrets-protocol:make-in-memory-secret-store))
        (ref (secrets-protocol:make-secret-ref :name "svc" :key "missing")))
    (ok (signals (secrets-protocol:resolve-secret store ref)
                 'secrets-protocol:secrets-error))))

(deftest resolve-secret-use-value
  (let* ((store (secrets-protocol:make-in-memory-secret-store))
         (ref (secrets-protocol:make-secret-ref :name "svc" :key "missing"))
         (got nil))
    (handler-bind ((secrets-protocol:secrets-error
                    (lambda (c)
                      (use-value "fallback" c))))
      (setf got (secrets-protocol:resolve-secret store ref)))
    (ok (string= "fallback" got))))
