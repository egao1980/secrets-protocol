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
  (string-downcase
   (encoding-protocol:encode (token-bytes n :backend backend) :encoding :base16)))

(defun %base64url (octets)
  "URL-safe base64 without padding."
  (encoding-protocol:encode octets :encoding :base64url :pad nil))

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

(defun unix-ms-now ()
  "Unix epoch milliseconds (second resolution + internal-time fraction)."
  (let* ((unix-sec (- (get-universal-time) 2208988800))
         (frac (mod (get-internal-real-time) internal-time-units-per-second)))
    (+ (* unix-sec 1000)
       (floor (* frac 1000) internal-time-units-per-second))))

(defun %uuid-string (octets)
  (flet ((hex (start end)
           (with-output-to-string (out)
             (loop for i from start below end
                   do (format out "~2,'0x" (aref octets i))))))
    (string-downcase
     (format nil "~a-~a-~a-~a-~a"
             (hex 0 4) (hex 4 6) (hex 6 8) (hex 8 10) (hex 10 16)))))

(defun make-uuid-v7 (&key unix-ms random-bytes (backend *secrets-backend*))
  "RFC 9562 UUID version 7 string.
   RANDOM-BYTES is 10 CSPRNG octets (or drawn from BACKEND).
   UNIX-MS defaults to UNIX-MS-NOW."
  (let* ((ms (or unix-ms (unix-ms-now)))
         (rand (or random-bytes
                   (backend-random-bytes (%ensure-backend backend) 10)))
         (octets (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (unless (= (length rand) 10)
      (error 'secrets-error :message "UUID v7 needs 10 random bytes"))
    (setf (aref octets 0) (ldb (byte 8 40) ms)
          (aref octets 1) (ldb (byte 8 32) ms)
          (aref octets 2) (ldb (byte 8 24) ms)
          (aref octets 3) (ldb (byte 8 16) ms)
          (aref octets 4) (ldb (byte 8 8) ms)
          (aref octets 5) (ldb (byte 8 0) ms))
    (replace octets rand :start1 6)
    (setf (aref octets 6) (logior (logand (aref octets 6) #x0f) #x70)
          (aref octets 8) (logior (logand (aref octets 8) #x3f) #x80))
    (%uuid-string octets)))

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
