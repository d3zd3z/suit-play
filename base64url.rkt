#lang racket/base

(provide base64url-encode-stream
	 base64url-encode
	 base64url-decode-stream
	 base64url-decode)

;;; The regular base64 encoding only does the regular encoding.  This
;;; is copied from Racket's collect/net/base64.rkt, and therefore will
;;; be covered by the LGPL.

(define ranges '([#"AZ" 0] [#"az" 26] [#"09" 52] [#"--" 62] [#"__" 63]))

(define-values (base64url-digit digit-base64url)
  (let ([bd (make-vector 256 #f)] [db (make-vector 64 #f)])
    (for ([r ranges]
	  #:when #t
	  [i (in-range (bytes-ref (car r) 0) (add1 (bytes-ref (car r) 1)))]
	  [n (in-naturals (cadr r))])
      (vector-set! bd i n)
      (vector-set! db n i))
    (values (vector->immutable-vector bd)
	    (vector->immutable-vector db))))

(define =byte (bytes-ref #"=" 0))
(define ones
  (vector->immutable-vector
    (list->vector (for/list ([i (in-range 9)]) (sub1 (arithmetic-shift 1 i))))))

(define (base64url-decode-stream in out)
  (let loop ([data 0] [bits 0])
    (if (>= bits 8)
      (let ([bits (- bits 8)])
	(write-byte (arithmetic-shift data (- bits)) out)
	(loop (bitwise-and data (vector-ref ones bits)) bits))
      (let ([c (read-byte in)])
	(unless (or (eof-object? c) (eq? c =byte))
	  (let ([v (vector-ref base64url-digit c)])
	    (if v
	      (loop (+ (arithmetic-shift data 6) v) (+ bits 6))
	      (loop data bits))))))))

(define (base64url-encode-stream in out)
  (let loop ([data 0] [bits 0])
    (define (write-char)
      (write-byte (vector-ref digit-base64url (arithmetic-shift data (- 6 bits)))
		  out))
    (if (>= bits 6)
      (let ([bits (- bits 6)])
	(write-char)
	(loop (bitwise-and data (vector-ref ones bits)) bits))
      (let ([c (read-byte in)])
	(if (eof-object? c)
	  ;; Flush extra bits
	  (begin
	    (when (> bits 0) (write-char)))
	  (loop (+ (arithmetic-shift data 8) c) (+ bits 8)))))))

(define (base64url-decode src)
  (let ([s (open-output-bytes)])
    (base64url-decode-stream (open-input-bytes src) s)
    (get-output-bytes s)))

(define (base64url-encode src)
  (let ([s (open-output-bytes)])
    (base64url-encode-stream (open-input-bytes src) s)
    (get-output-bytes s)))
