(defsystem "secrets-protocol"
  :version "0.1.1"
  :description "CLOS secrets protocol for cl-stack (CSPRNG, tokens, compare, UUID, password KDF)"
  :author "egao1980"
  :license "MIT"
  :depends-on ("encoding-protocol")
  :properties (:cl-repo (:ci (:sources (("encoding-protocol" :oci)))))

  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "conditions")
               (:file "protocol"))
  :in-order-to ((test-op (test-op "secrets-protocol/tests"))))

(defsystem "secrets-protocol/tests"
  :depends-on ("secrets-protocol" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "protocol-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
