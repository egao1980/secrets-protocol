(in-package #:secrets-protocol/tests)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (load (asdf:system-relative-pathname "secrets-protocol" "examples/store.lisp")))

(deftest store-demo-runs
  (ok (string= "s3cret" (secrets-protocol/demo:run (make-broadcast-stream)))))
