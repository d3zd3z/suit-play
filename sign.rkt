#! /usr/bin/env racket
#lang racket/base

(require asn1
	 crypto
	 crypto/libcrypto
	 racket/file
	 racket/port
	 "cbor.rkt"
	 "dump.rkt"
	 "keys.rkt")

;;; The library returns the ECDSA key in a simple ASN1 value.  We want
;;; to encode them as just the two raw values.
(define Ecdsa-Sig-Value
  (SEQUENCE
    [r INTEGER]
    [s INTEGER]))

(define (extract-ecdsa-sig sig)
  (define value (bytes->asn1/DER Ecdsa-Sig-Value sig))
  (define r (integer->bytes (hash-ref value 'r)))
  (define s (integer->bytes (hash-ref value 's)))
  ;; TODO: Fix this to left pad.  This will currently fail about 1/128
  ;; times this is run.
  (when (or (< (bytes-length r) 32)
	    (< (bytes-length r) 32))
    (error "TODO: Implement padding"))
  (bytes-append r s))

;;; Sign a file using a specific key, resulting in a wrapped cbor
;;; object.

(define (make-signatory blob key)
  (define to-be-signed
    (encode-cbor `("Signature"
		   ,(encode-cbor (hasheqv 3 0))
		   ,(encode-cbor (hasheqv 1 -7))
		   #""
		   ,blob)))
  (define tob-hash (digest 'sha256 to-be-signed))
  (define sig (pk-sign key tob-hash))
  ;; (call-with-output-file "debug.asn1"
  ;;		 (lambda (out) (write-bytes sig out)))
  (extract-ecdsa-sig sig))

;;; Generate the signed cose.
(define (make-cose blob key)
  (define sig (make-signatory blob key))
  (encode-cbor `(,(encode-cbor (hasheqv 3 0))
		  ,(hasheqv)
		  ,blob
		  ((,(encode-cbor (hasheqv 1 -7))
		     #""
		     ,sig)))))

(module+ main
  (require racket/cmdline)

  (define key-file (make-parameter #f))
  (define input-file (make-parameter #f))
  (define output-file (make-parameter #f))

  (define arg-table
    (command-line
      #:once-each
      [("-k" "--key") kf
		      "The private key is in <kf>"
		      (key-file kf)]
      [("-i" "--input") inp
			"File to be signed is <inp>"
			(input-file inp)]
      [("-o" "--output") out
			 "Signed COSE written to <out>"
			 (output-file out)]))

  (define failures #f)
  (define (must item desc)
    (unless item
      (eprintf "error: ~A~%" desc)
      (set! failures #t)))
  (must (key-file) "Must specify -k/--key")
  (must (input-file) "Must specify -i/--input")
  (must (output-file) "Must specify -o/--output")
  (when failures
    (eprintf "*** stopping~%")
    (exit 1))

  ;;; Before starting, we have to load the crypto factories.
  (crypto-factories (list libcrypto-factory))

  (let* ([key (load-ec-key (key-file))]
	 [blob (port->bytes (open-input-file (input-file)))]
	 [cose (make-cose blob key)])
    (call-with-output-file (output-file)
			   (lambda (out) (write-bytes cose out))))
  )
