(in-package #:secrets-protocol/tests)

(deftest random-bytes-length
  (ok (= 16 (length (secrets-protocol:random-bytes 16))))
  (ok (not (equalp (secrets-protocol:random-bytes 8)
                   (secrets-protocol:random-bytes 8)))))

(deftest token-hex-and-urlsafe
  (let ((h (secrets-protocol:token-hex 8))
        (u (secrets-protocol:token-urlsafe 8)))
    (ok (= 16 (length h)))
    (ok (every (lambda (c) (digit-char-p c 16)) h))
    (ok (>= (length u) 10))
    (ok (not (find #\= u)))))

(deftest constant-time-equal
  (let ((a (ironclad:hex-string-to-byte-array "010203"))
        (b (ironclad:hex-string-to-byte-array "010203"))
        (c (ironclad:hex-string-to-byte-array "010204")))
    (ok (secrets-protocol:constant-time-equal a b))
    (ng (secrets-protocol:constant-time-equal a c))
    (ng (secrets-protocol:constant-time-equal a (ironclad:hex-string-to-byte-array "01")))))

(deftest uuid-v4
  (let ((u (secrets-protocol:uuid :version :v4)))
    (ok (= 36 (length u)))
    (ok (char= #\- (char u 8)))))

(deftest password-argon2i-roundtrip
  (let* ((hash (secrets-protocol:hash-password "s3cret" :algorithm :argon2i)))
    (ok (secrets-protocol:verify-password "s3cret" hash))
    (ng (secrets-protocol:verify-password "wrong" hash))))

(deftest password-pbkdf2-roundtrip
  (let* ((hash (secrets-protocol:hash-password "s3cret" :algorithm :pbkdf2-sha256)))
    (ok (secrets-protocol:verify-password "s3cret" hash))
    (ng (secrets-protocol:verify-password "nope" hash))))
