;;;; Offline secret-ref demo — refs hold names, never material.
;;;;   sbcl --load examples/store.lisp

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (find-package :secrets-protocol)
    (require :asdf)
    (asdf:load-system "secrets-protocol/store")))

(defpackage #:secrets-protocol/demo
  (:use #:cl #:secrets-protocol)
  (:export #:run))

(in-package #:secrets-protocol/demo)

(defun run (&optional (stream *standard-output*))
  "Resolve a ref, prove the journal line has no material. Returns the material."
  (let* ((store (make-in-memory-secret-store
                 :secrets '(("vault" "token" "s3cret"))))
         (ref (make-secret-ref :name "vault" :key "token" :inject :env))
         (journal `(:secret-ref (:name ,(secret-ref-name ref)
                                 :key ,(secret-ref-key ref)
                                 :inject ,(secret-ref-inject ref))))
         (material (resolve-secret store ref)))
    (format stream "~&; journal ~s~%" journal)
    (assert (secret-ref-p ref))
    (assert (not (slot-exists-p ref (intern "MATERIAL" :secrets-protocol))))
    (assert (null (search "s3cret" (prin1-to-string journal) :test #'char-equal)))
    (assert (string= "s3cret" material))
    (let ((missing (make-secret-ref :name "vault" :key "missing")))
      (handler-bind ((secrets-error (lambda (c) (use-value "fallback" c))))
        (assert (string= "fallback" (resolve-secret store missing)))))
    (format stream "~&; resolved (not journaled) length=~d~%" (length material))
    material))

#+sbcl
(when (and *load-truename*
           (equal (pathname-name *load-truename*) "store")
           (find "examples/store.lisp" sb-ext:*posix-argv* :test #'search))
  (run)
  (uiop:quit 0))
