#lang racket

(require
  (only-in file/sha1 hex-string->bytes)
  crypto
  crypto/libcrypto
  libuuid
  "dump.rkt"
  "cbor.rkt")

;; TODO: Shouldn't really set this here.
(crypto-factories (list libcrypto-factory))

;;; Generate a UUID, and turn it into binary.  This isn't actually
;;; correct (uuids have weird endiannesses in their encodings).
(define (gen-uuid)
  (define uuid (uuid-generate))
  (hex-string->bytes (string-replace uuid "-" "")))

;;; Suit support

(define (make-manifest)
  `(1
    ;; Digest info.  It isn't clear what this is supposed to be.  So,
    ;; make something up.
    (36 #"SHA256")

    ;; Text reference.  Just make one up.
    ,(digest 'sha256 #"Hello world")

    ;; nonce, just put 16 bytes here
    #"wjqovnzjeirowyqu"

    ;; Sequence number, use a timestamp.
    ,(current-seconds)

    ;; Preconditions
    ((1 ,(gen-uuid)) ;; Vendor, binary uuid.
     (2 ,(gen-uuid))
     (3 ,(gen-uuid)))

    ;; PostConditions.
    ()

    ;; directives
    ()

    ;; resources
    ;; No real idea what some of these are supposed to be, but let's
    ;; pretend this meaningfully maps to a resource.
    ((2 ,(hasheqv 1 "slot0") 63179 ,(digest 'sha256 #"the image") #"")
     (1 ,(hasheqv 1 "slot1") 127233 ,(digest 'sha256 #"new image") #"2"))

    ;; processors
    ((4 #"" #"2" #""))

    ;; targets.  Here actually describes the payload.
    (((#"application") "slot1" #"binary" #"0"))

    ;; extensions
    #hasheqv()))
