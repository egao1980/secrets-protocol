(defsystem "secrets-protocol"
  :version "0.1.0"
  :description "CLOS secrets protocol for cl-stack (CSPRNG, tokens, compare, UUID, password KDF)"
  :author "egao1980"
  :license "MIT"
  :depends-on ()
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "conditions")
               (:file "protocol"))
  :in-order-to ((test-op (test-op "secrets-protocol/tests"))))

(defsystem "secrets-backend-os"
  :version "0.1.0"
  :description "OS CSPRNG + uuid backend for secrets-protocol (via Ironclad)"
  :author "egao1980"
  :license "MIT"
  :depends-on ("secrets-protocol" "ironclad" "uuid" "babel")
  :serial t
  :pathname "src/backend-os"
  :components ((:file "package")
               (:file "backend"))
  :in-order-to ((test-op (test-op "secrets-protocol/tests"))))

(defsystem "secrets-protocol/tests"
  :depends-on ("secrets-backend-os" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "secrets-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
