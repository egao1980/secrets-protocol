(in-package #:secrets-protocol/tests)

;;; Protocol-only. Ironclad backend lives in crypto-backend-ironclad.

(deftest no-backend-signals
  (let ((secrets-protocol:*secrets-backend* nil))
    (ok (signals (secrets-protocol:random-bytes 8)
                 'secrets-protocol:secrets-error))))

(deftest constant-time-equal-pure
  (let ((a (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3)))
        (b (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3)))
        (c (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(1 2 4))))
    (ok (secrets-protocol:constant-time-equal a b))
    (ng (secrets-protocol:constant-time-equal a c))))
