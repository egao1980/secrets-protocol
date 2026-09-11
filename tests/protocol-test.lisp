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

(deftest uuid-v7-rfc9562-vector
  ;; RFC 9562 Appendix A.4 (unix_ts_ms / rand_a / rand_b).
  (let* ((rand #(#xCC #xC3 #x18 #xC4 #xDC #x0C #x0C #x07 #x39 #x8F))
         (u (secrets-protocol:make-uuid-v7 :unix-ms #x017F22E279B0
                                           :random-bytes rand)))
    (ok (string= "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" u))
    (ok (char= #\7 (char u 14)))
    (ok (find (char u 19) "89ab"))))
