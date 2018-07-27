#lang racket/base

(require
  rackunit
  "dump.rkt"
  "cbor.rkt")

;;; TODO: Check against canonical encodings rather than just checking
;;; that round trip works.

(define (check-same item [message ""])
  (define encoded (encode-cbor item))
  (define decoded (decode-cbor encoded))
  ; (printf "Cbor for: ~a~%" item)
  ; (dump encoded)
  (check-equal? item decoded message))

;;; Test around powers of 256, up to large enough to resemble RSA
;;; values.
(for ([digits (in-range 8 2049 8)])
  (define base (expt 2 digits))
  (for ([delta (in-range -3 3)])
    (check-same (+ base delta))
    (check-same (- -1 base delta))))
