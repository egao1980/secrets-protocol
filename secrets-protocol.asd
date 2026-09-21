(defsystem "secrets-protocol"
  :version "0.1.3"
  :description "CLOS secrets protocol for cl-stack (CSPRNG, tokens, compare, UUID, password KDF)"
  :author "egao1980"
  :license "MIT"
  :depends-on ("encoding-protocol")
  :properties (:cl-repo
               (:ci (:with ("secrets-protocol/store"))))
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "conditions")
               (:file "protocol"))
  :in-order-to ((test-op (test-op "secrets-protocol/tests"))))

(defsystem "secrets-protocol/store"
  :version "0.1.0"
  :description "Secret refs + store protocol for secrets-protocol (no material on refs)"
  :author "egao1980"
  :license "MIT"
  :depends-on ("secrets-protocol")
  :serial t
  :pathname "src/store"
  :components ((:file "store"))
  :in-order-to ((test-op (test-op "secrets-protocol/tests"))))

(defsystem "secrets-protocol/tests"
  :depends-on ("secrets-protocol" "secrets-protocol/store" "rove")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "protocol-test")
               (:file "store-test")
               (:file "demo-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
