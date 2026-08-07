(in-package #:secrets-backend-os)

(defclass os-secrets-backend (secrets-protocol:secrets-backend) ())

(defun make-os-secrets-backend ()
  (make-instance 'os-secrets-backend))

(defun use-os-secrets-backend ()
  (setf secrets-protocol:*secrets-backend* (make-os-secrets-backend)))

(defmethod secrets-protocol:backend-random-bytes ((backend os-secrets-backend) n)
  (declare (ignore backend))
  (ironclad:random-data n))

(defmethod secrets-protocol:backend-uuid ((backend os-secrets-backend) &key (version :v4))
  (declare (ignore backend))
  (ecase version
    ((:v4 :4)
     (string-downcase (princ-to-string (uuid:make-v4-uuid))))
    ((:v7 :7)
     (error 'secrets-protocol:secrets-error
            :message "UUID v7 not available in this backend yet"))))

(defun %hex (octets)
  (with-output-to-string (s)
    (loop for b across octets do (format s "~2,'0x" b))))

(defun %unhex (hex)
  (ironclad:hex-string-to-byte-array hex))

(defun %encode-hash (alg params salt digest)
  (format nil "~a$~a$~a$~a" alg params (%hex salt) (%hex digest)))

(defun %parse-hash (hash)
  "→ (values alg params-string salt digest)"
  (let ((parts (uiop:split-string hash :separator '(#\$))))
    (unless (= (length parts) 4)
      (error 'secrets-protocol:secrets-error :message "malformed password hash"))
    (destructuring-bind (alg params salt-hex digest-hex) parts
      (values (intern (string-upcase alg) :keyword)
              params
              (%unhex salt-hex)
              (%unhex digest-hex)))))

(defun %parse-params (params)
  "Parse k=v,k=v → plist of keywords to integers."
  (mapcan (lambda (pair)
            (let* ((kv (uiop:split-string pair :separator '(#\=)))
                   (k (intern (string-upcase (first kv)) :keyword))
                   (v (parse-integer (second kv))))
              (list k v)))
          (uiop:split-string params :separator '(#\,))))

(defmethod secrets-protocol:backend-password-hash
    ((backend os-secrets-backend) password &key (algorithm :argon2i))
  (declare (ignore backend))
  (let* ((password (coerce password '(simple-array (unsigned-byte 8) (*))))
         (alg algorithm))
    (ecase alg
      ((:argon2i)
       (let* ((salt (ironclad:random-data 16))
              (m 16) (t-cost 2) (out-len 32)
              (kdf (ironclad:make-kdf :argon2i :block-count m))
              (digest (ironclad:derive-key kdf password salt t-cost out-len)))
         (%encode-hash "argon2i" (format nil "m=~d,t=~d" m t-cost) salt digest)))
      ((:pbkdf2 :pbkdf2-sha256)
       (let* ((salt (ironclad:random-data 16))
              (iters 100000) (out-len 32)
              (kdf (ironclad:make-kdf :pbkdf2 :digest :sha256))
              (digest (ironclad:derive-key kdf password salt iters out-len)))
         (%encode-hash "pbkdf2-sha256" (format nil "i=~d" iters) salt digest))))))

(defmethod secrets-protocol:backend-password-verify
    ((backend os-secrets-backend) password hash)
  (declare (ignore backend))
  (multiple-value-bind (alg params salt expected) (%parse-hash hash)
    (let* ((password (coerce password '(simple-array (unsigned-byte 8) (*))))
           (plist (%parse-params params))
           (got
            (ecase alg
              ((:argon2i)
               (ironclad:derive-key
                (ironclad:make-kdf :argon2i :block-count (getf plist :m))
                password salt (getf plist :t) (length expected)))
              ((:pbkdf2-sha256)
               (ironclad:derive-key
                (ironclad:make-kdf :pbkdf2 :digest :sha256)
                password salt (getf plist :i) (length expected))))))
      (secrets-protocol:constant-time-equal got expected))))

(use-os-secrets-backend)
