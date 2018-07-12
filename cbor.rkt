#lang racket

(require
  binaryio
  "dump.rkt")

(provide
  (struct-out cbor-tag)
  (struct-out cbor-null)
  write-cbor)

;;; CBOR tags need their own representation, which we represent with
;;; this transparent struct.  The first field is the tag number, and
;;; the second is the item.
(struct cbor-tag (tag data) #:transparent)

;;; The null value is defined by this empty struct, use cbor-null? to
;;; check for it.
(struct cbor-null ())

;;; Perform body with writes going to a byte-string that is returned.
(define-syntax-rule (let-to-bytes body ...)
  (with-output-to-bytes
    (lambda ()
      body ...)))

;;; This file performs a conversion between scheme types and CBOR.
;;; Conversions are done canonically.  It is not designed to represent
;;; arbitrary types, but instead to provide a full mapping between the
;;; CBOR representation and a SEXP representation.

;;; A less than operator defined for cbor.
(define (cbor-key<? a b)
  (define a-key (car a))
  (define b-key (car b))
  (define a-len (bytes-length a-key))
  (define b-len (bytes-length b-key))
  (cond [(< a-len b-len) #t]
	[(> a-len b-len) #f]
	[else (bytes<? a-key b-key)]))

(define (write-tagval tag value)
  (cond [(< value 24)
	 (write-byte (bitwise-ior (arithmetic-shift tag 5) value))]
	[(< value 256)
	 (write-byte (bitwise-ior (arithmetic-shift tag 5) 24))
	 (write-byte value)]
	[(< value 65536)
	 (write-byte (bitwise-ior (arithmetic-shift tag 5) 25))
	 (write-integer value 2 #f)]
	[(< value 4294967295)
	 (write-byte (bitwise-ior (arithmetic-shift tag 5) 26))
	 (write-integer value 4 #f)]
	[else
	 (write-byte (bitwise-ior (arithmetic-shift tag 5) 27))
	 (write-integer value 8 #f)]))

;;; Write a hash table out.  This takes an alist, pre-encodes all of
;;; the keys so that they can be sorted according to the CBOR rules,
;;; and then outputs everything.
(define (write-hash alist)
  (define (encode-key pair)
    (cons (let-to-bytes (write-cbor (car pair)))
	  (cdr pair)))
  (define items (map encode-key alist))
  (for ([kv (in-list (sort items cbor-key<?))])
    (write-bytes (car kv))
    (write-cbor (cdr kv))))

(define (write-cbor datum)
  (cond [(exact-nonnegative-integer? datum)
	 (write-tagval 0 datum)]
	;; TODO: Handle integers that don't fit in 64-bits.
	[(integer? datum)
	 (write-tagval 1 (- -1 datum))]
	[(bytes? datum)
	 (write-tagval 2 (bytes-length datum))
	 (write-bytes datum)]
	[(string? datum)
	 (let ([encoded (string->bytes/utf-8 datum)])
	   (write-tagval 3 (bytes-length encoded))
	   (write-bytes encoded))]

	[(cbor-tag? datum)
	 (write-tagval 6 (cbor-tag-tag datum))
	 (write-cbor (cbor-tag-data datum))]

	;; Special values.
	[(eq? datum #t)
	 (write-tagval 7 21)]
	[(eq? datum #f)
	 (write-tagval 7 20)]

	;; Handle the special cbor-null case.
	[(cbor-null? datum)
	 (write-tagval 7 22)]

	;; Treat a symbol like a string so we can use hasheq.
	[(symbol? datum)
	 (write-cbor (symbol->string datum))]

	;; Proper lists will be done as arrays.
	[(list? datum)
	 (write-tagval 4 (length datum))
	 (for ([elt (in-list datum)])
	   (write-cbor elt))]

	;; Vectors are also done as arrays.
	[(vector? datum)
	 (write-tagval 4 (vector-length datum))
	 (for ([elt (in-vector datum)])
	   (write-cbor elt))]

	;; Various hash tables are encoded as alists, since the keys
	;; have to be sorted.
	[(hash? datum)
	 (write-tagval 5 (hash-count datum))
	 (write-hash (hash->list datum))]

	;; TODO: Tags (and richer types from that) and no-content
	;; things.

	[else
	  (error "Unsupported CBOR item" datum)]))

;;; A convertor.
(define (cbor->bytes datum)
  (dump (let-to-bytes (write-cbor datum))))
