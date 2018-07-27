#lang racket/base

(require
  racket/port
  binaryio
  "dump.rkt")

(provide
  (struct-out cbor-tag)
  cbor-null-object cbor-null?
  write-cbor read-cbor
  encode-cbor decode-cbor
  integer->bytes bytes->integer
  tout)

;;; CBOR tags need their own representation, which we represent with
;;; this transparent struct.  The first field is the tag number, and
;;; the second is the item.  This is only used for tags beyond the
;;; basic ones defined by CBOR.
(struct cbor-tag (tag data) #:transparent)

;;; The null value is defined by this empty struct, use cbor-null? to
;;; check for it.
(struct cbor-null ())

;;; Create a single instance, and don't export the constructor.
(define cbor-null-object (cbor-null))

;;; Perform body with writes going to a byte-string that is returned.
(define-syntax-rule (let-to-bytes body ...)
  (with-output-to-bytes
    (lambda ()
      body ...)))

(define-syntax-rule (let-from-bytes (bstr) body ...)
  (with-input-from-bytes
    bstr
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
	[(< value 4294967296)
	 (write-byte (bitwise-ior (arithmetic-shift tag 5) 26))
	 (write-integer value 4 #f)]
	[else
	 (write-byte (bitwise-ior (arithmetic-shift tag 5) 27))
	 (write-integer value 8 #f)]))

;;; Reads a cbor tag/val, and returns two values, the tag, and the
;;; number associated with it.  The meaning of the number depends on
;;; the particular tag.
(define (read-tagval)
  (define tagval (read-byte))
  (define tag (arithmetic-shift tagval -5))
  (define value (bitwise-and tagval #x1f))
  (cond [(< value 24)
	 (values tag value)]
	[(= value 24)
	 (let ([value (read-byte)])
	   (values tag value))]
	[(= value 25)
	 (let ([value (read-integer 2 #f)])
	   (values tag value))]
	[(= value 26)
	 (let ([value (read-integer 4 #f)])
	   (values tag value))]
	[(= value 27)
	 (let ([value (read-integer 8 #f)])
	   (values tag value))]
	[else (error "Unsupported length in CBOR")]))

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

;;; Convert a large integer into a minimual number of bytes to
;;; represent it.  The representation is big-endian.
(define (integer->bytes num)
  (let loop ([result '()]
	     [num num])
    (if (positive? num)
      (loop (cons (bitwise-and num #xff) result)
	    (arithmetic-shift num -8))
      (list->bytes result))))

;;; Convert a byte sequence into the integer representing it (big
;;; endian).
(define (bytes->integer bstr)
  (for/fold ([result 0])
    ([byte (in-bytes bstr)])
    (bitwise-ior (arithmetic-shift result 8) byte)))

(define (write-cbor datum)
  (cond [(exact-nonnegative-integer? datum)
	 (if (>= datum (expt 2 64))
	   (let ([binary (integer->bytes datum)])
	     (write-tagval 6 2)
	     (write-cbor binary))
	   (write-tagval 0 datum))]
	;; TODO: Handle integers that don't fit in 64-bits.
	[(integer? datum)
	 (if (< datum (- (expt 2 64)))
	   (let* ([neg-datum (- -1 datum)]
		  [binary (integer->bytes neg-datum)])
	     (write-tagval 6 3)
	     (write-cbor binary))
	   (write-tagval 1 (- -1 datum)))]
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

(define (read-cbor)
  (define-values (tag value) (read-tagval))
  (case tag
    [(0) value]
    [(1) (- -1 value)]
    [(2) (read-bytes* value)]
    [(3) (bytes->string/utf-8 (read-bytes* value))]

    ;; Arbitrarily decide to read arrays as lists.
    [(4) (for/list ([i (in-range value)])
	   (read-cbor))]

    ;; When we read in maps, if the key is a string, make it a symbol,
    ;; so that the hasheqv will work.
    [(5) (let ([result (make-hasheqv)])
	   (for ([i (in-range value)])
	     (let* ([key0 (read-cbor)]
		    [value (read-cbor)]
		    [key (if (string? key0)
			   (string->symbol key0)
			   key0)])
	       (hash-set! result key value)))
	   result)]
    [(6) (let ([item (read-cbor)])
	   (case value
	     [(2) (bytes->integer item)]
	     [(3) (- -1 (bytes->integer item))]
	     [else (cbor-tag value item)]))]
    [(7) (case value
	   [(20) #f]
	   [(21) #t]
	   [(22) (cbor-null)]
	   [else (error "TODO: Support other #7.xxx value" value)])]

    [else (error "Unsupported tag")]))

;;; A convertor.
(define (encode-cbor datum)
  (let-to-bytes (write-cbor datum)))

(define (tout datum)
  (dump (encode-cbor datum)))

(define (decode-cbor bstr)
  (let-from-bytes (bstr)
		  (read-cbor)))
