(in-package #:secrets-protocol)

;;; Secret refs name material; they never hold it. Resolve via a store.

(defclass secret-ref ()
  ((name :initarg :name :reader secret-ref-name)
   (key :initarg :key :reader secret-ref-key)
   (inject :initarg :inject :reader secret-ref-inject :initform :env))
  (:documentation
   "Handle for a named secret. NAME+KEY identify the entry; INJECT is
:env or :file. Material is never stored on the ref."))

(defun secret-ref-p (object)
  (typep object 'secret-ref))

(defun make-secret-ref (&key name key (inject :env))
  (check-type name string)
  (check-type key string)
  (unless (member inject '(:env :file))
    (error 'secrets-error
           :message (format nil "inject must be :env or :file, got ~s" inject)))
  (make-instance 'secret-ref :name name :key key :inject inject))

(defclass secret-store () ()
  (:documentation "Protocol class. RESOLVE-SECRET returns string material."))

(defun secret-store-p (object)
  (typep object 'secret-store))

(defgeneric resolve-secret (store ref)
  (:documentation
   "Return string material for REF from STORE.
Signals SECRETS-ERROR when missing; restart USE-VALUE supplies a value."))

(defgeneric put-secret (store name key material)
  (:documentation "Store string MATERIAL under NAME+KEY."))

(defclass in-memory-secret-store (secret-store)
  ((table :initarg :table :accessor in-memory-secret-store-table
          :initform (make-hash-table :test 'equal)))
  (:documentation "Hash-table store for tests. Keys are (NAME . KEY)."))

(defun in-memory-secret-store-p (object)
  (typep object 'in-memory-secret-store))

(defun make-in-memory-secret-store (&key secrets)
  "SECRETS is a list of (NAME KEY MATERIAL) triples."
  (let ((store (make-instance 'in-memory-secret-store)))
    (dolist (entry secrets store)
      (destructuring-bind (name key material) entry
        (put-secret store name key material)))))

(defmethod put-secret ((store in-memory-secret-store) name key material)
  (check-type name string)
  (check-type key string)
  (check-type material string)
  (setf (gethash (cons name key) (in-memory-secret-store-table store)) material)
  material)

(defmethod resolve-secret ((store in-memory-secret-store) (ref secret-ref))
  (multiple-value-bind (material found)
      (gethash (cons (secret-ref-name ref) (secret-ref-key ref))
               (in-memory-secret-store-table store))
    (if found
        material
        (restart-case
            (error 'secrets-error
                   :message (format nil "secret ~s / ~s not found"
                                    (secret-ref-name ref)
                                    (secret-ref-key ref)))
          (use-value (value)
            :report "Use a supplied secret value instead"
            :interactive (lambda ()
                           (format *query-io* "Secret value: ")
                           (force-output *query-io*)
                           (list (read *query-io*)))
            value)))))
