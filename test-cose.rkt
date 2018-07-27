#lang racket

(require
  crypto
  crypto/libcrypto
  json
  (only-in file/sha1 hex-string->bytes)
  "base64url.rkt"
  "dump.rkt"
  "cose.rkt"
  "cbor.rkt")

(crypto-factories (list libcrypto-factory))

;;; Headers = (
;;;   protected : empty_or_serialized_map,
;;;   unprotected : header_map
;;; )
;;;
;;; header_map = {
;;;   Generic_Headers,
;;;   * label => values
;;; }
;;;
;;; Generic_Headers = (
;;;     ? 1 => int / tstr,  ; algorithm identifier
;;;     ? 2 => [+label],    ; criticality
;;;     ? 3 => tstr / int,  ; content type
;;;     ? 4 => bstr,        ; key identifier
;;;     ? 5 => bstr,        ; IV
;;;     ? 6 => bstr,        ; Partial IV
;;;     ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
;;; )
;;;
;;; empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
;;;
;;; COSE_Sign1 = [
;;;   Headers,
;;;   payload : bstr / nil,
;;;   signature : bstr
;;; ]
;;;
;;; Algorithms from RFC8152:
;;;   ES256  -7   ECDSA w/ SHA-256
;;;   ES384  -35  ECDSA w/ SHA-384
;;;   ES512  -36  ECDSA w/ SHA-512
;;;
;;; Key types:
;;;   prime256v1 (P-256): 1.2.840.10045.3.1.7
;;;   secp384r1  (P-384): 1.3.132.0.34
;;;   secp521r1  (P-521): 1.3.132.0.35

;;; Nested hash refs that walk a list of keys to get to the item.
(define (hash-refs tbl keys)
  (cond [(empty? keys) tbl]
	[else (hash-refs (hash-ref tbl (car keys)) (cdr keys))]))

(define (indent level)
  (for ([i (in-range level)])
    (display "  ")))

;;; Extract a keypair from the json representation of it.
(define (get-key jsn)
  (define alg1 (hash-refs jsn '(input sign0 unprotected alg)))
  (define alg2 (hash-refs jsn '(input sign0 alg)))
  (unless (equal? alg1 alg2)
    (error "Inconsistent algorithms specified" alg1 alg2))
  (define kty (hash-refs jsn '(input sign0 key kty)))
  (case kty
    [(EC) (get-ec-key (hash-refs jsn '(input sign0 key)))]
    [else (error "Unknown key type" kty)]))

;;; Extract a json EC key.
(define (get-ec-key jsn)
  (define oid (case (hash-ref jsn 'crv)
		[("P-256") '(1 2 840 10045 3 1 7)]
		;; These need the padding below to be adjusted.
		[("P-384") '(1 3 132 0 34) (error "TODO")]
		[("P-521") '(1 3 132 0 35) (error "TODO")]
		[else (error "Unsupported curve")]))
  (define x (base64url-decode (string->bytes/utf-8 (hash-ref jsn 'x))))
  (define y (base64url-decode (string->bytes/utf-8 (hash-ref jsn 'y))))
  (define xy (bytes-append #"\x04" (pad x 32) (pad y 32)))
  (define d (bytes->integer (base64url-decode (string->bytes/utf-8 (hash-ref jsn 'y)))))
  (datum->pk-key
    `(ec private ,oid ,xy ,d)
    'rkt-private))

;;; Pad a bytestring on the left with zeros to make it the given
;;; length.
(define (pad x num)
  (define len (bytes-length x))
  (cond [(> len num) (error "Binary value too large")]
	[(= len num) x]
	[else
	  (pad (bytes-append #"\0" x) num)]))

;;; Show the structure of a json hashtable-based item.
(define (show-structure jsn #:level [level 0]
			#:show-values [show-values #f])
  (cond [(hash? jsn)
	 (for ([(k v) jsn])
	   (indent level)
	   (display k)
	   (display ":\n")
	   (show-structure v #:level (add1 level)
			   #:show-values show-values))]
	[else
	  (when show-values
	    (indent level)
	    (display jsn)
	    (newline))]))

(define (decode-input jsn) jsn)
(define (decode-output jsn) jsn)
(define (decode-intermediates jsn) jsn)

;;; Decode one of the test cases.
(define (decode-example jsn)
  ;; (show-structure jsn #:show-values #t)
  (define title (hash-ref jsn 'title))
  (define output (hex-string->bytes (hash-refs jsn '(output cbor))))
  (define dec-output (decode-cbor output))
  (define pkey (get-ec-key (hash-refs jsn '(input sign0 key))))
  (define external
    (hex-string->bytes (hash-refs jsn '(input sign0 external))))
  ;; (define input (decode-input (hash-ref jsn 'input)))
  ;; (define output (decode-output (hash-ref jsn 'output)))
  ;; (define intermediates (decode-intermediates (hash-ref jsn 'intermediates)))
  ;; (printf "input ~a~%" (hash-keys input))
  ;; (printf "output ~a~%" (hash-keys output))
  ;; (printf "intermediates ~a~%" (hash-keys intermediates))
  ;; (printf "external\n") (dump external)
  (check-cose dec-output #:external external)
  pkey)

;;; Extract the keypair 

(define (load1)
  (call-with-input-file
    "Examples/sign1-tests/sign-pass-02.json"
    (lambda (in)
      (decode-example (read-json in)))))
