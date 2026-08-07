(in-package #:secrets-protocol)

;;; Python secrets + Java SecureRandom + password KDFs.
;;; Digests/AEAD live in crypto-protocol.

(defclass secrets-backend () ())

(defvar *secrets-backend* nil)

(defun %ensure-backend (&optional (backend *secrets-backend*))
  (or backend
      (error 'secrets-error
             :message "*secrets-backend* is nil — load crypto-backend-ironclad")))

(defgeneric backend-random-bytes (backend n)
  (:documentation "Return N cryptographically strong random octets."))

(defgeneric backend-uuid (backend &key version)
  (:documentation "Return UUID string. VERSION :v4 (required) or :v7."))

(defgeneric backend-password-hash (backend password &key algorithm)
  (:documentation "Return opaque hash string/octets for PASSWORD."))

(defgeneric backend-password-verify (backend password hash)
  (:documentation "T if PASSWORD matches HASH."))

(defun random-bytes (n &key (backend *secrets-backend*))
  (check-type n (integer 0 *))
  (backend-random-bytes (%ensure-backend backend) n))

(defun token-bytes (n &key (backend *secrets-backend*))
  "N bytes of CSPRNG output (Python secrets.token_bytes)."
  (random-bytes n :backend backend))

(defun token-hex (n &key (backend *secrets-backend*))
  "Hex string of N random bytes (2N chars)."
  (let ((bytes (token-bytes n :backend backend)))
    (with-output-to-string (s)
      (loop for b across bytes do (format s "~2,'0x" b)))))

(defun %base64url (octets)
  "URL-safe base64 without padding."
  (let* ((table "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
         (len (length octets))
         (out (make-array (* 4 (ceiling len 3)) :element-type 'character :fill-pointer 0)))
    (labels ((enc (a b c pad)
               (let ((n (logior (ash a 16) (ash (or b 0) 8) (or c 0))))
                 (vector-push (char table (ldb (byte 6 18) n)) out)
                 (vector-push (char table (ldb (byte 6 12) n)) out)
                 (unless (>= pad 2)
                   (vector-push (char table (ldb (byte 6 6) n)) out))
                 (unless (>= pad 1)
                   (vector-push (char table (ldb (byte 6 0) n)) out)))))
      (loop for i from 0 below len by 3
            do (let* ((remain (- len i))
                      (a (aref octets i))
                      (b (and (>= remain 2) (aref octets (+ i 1))))
                      (c (and (>= remain 3) (aref octets (+ i 2))))
                      (pad (max 0 (- 3 remain))))
                 (enc a b c pad))))
    (coerce out 'simple-string)))

(defun token-urlsafe (n &key (backend *secrets-backend*))
  "URL-safe base64 of N random bytes (Python secrets.token_urlsafe)."
  (%base64url (token-bytes n :backend backend)))

(defun constant-time-equal (a b)
  "Timing-safe equality for octet vectors (Python compare_digest / JCA isEqual)."
  (let ((a (coerce a '(simple-array (unsigned-byte 8) (*))))
        (b (coerce b '(simple-array (unsigned-byte 8) (*)))))
    (let ((res (if (= (length a) (length b)) 0 1)))
      (loop for i from 0 below (min (length a) (length b))
            do (setf res (logior res (logxor (aref a i) (aref b i)))))
      (zerop res))))

(defun uuid (&key (version :v4) (backend *secrets-backend*))
  (backend-uuid (%ensure-backend backend) :version version))

(defun %password-octets (password)
  (etypecase password
    ((simple-array (unsigned-byte 8) (*)) password)
    ((vector (unsigned-byte 8)) (coerce password '(simple-array (unsigned-byte 8) (*))))
    (string
     (let ((encode (find-symbol "STRING-TO-OCTETS" :babel)))
       (unless (and encode (fboundp encode))
         (error 'secrets-error :message "babel required to hash string passwords"))
       (funcall encode password :encoding :utf-8)))))

(defun hash-password (password &key (algorithm :argon2i) (backend *secrets-backend*))
  (backend-password-hash (%ensure-backend backend) (%password-octets password)
                         :algorithm algorithm))

(defun verify-password (password hash &key (backend *secrets-backend*))
  (backend-password-verify (%ensure-backend backend) (%password-octets password) hash))
