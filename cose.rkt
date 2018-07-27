#lang racket

(require
  (only-in file/sha1 hex-string->bytes)
  crypto
  crypto/libcrypto
  crypto/sodium
  "dump.rkt"
  "cbor.rkt")

(provide check-cose)

;;; Set this up, best not here.
(crypto-factories (list libcrypto-factory sodium-factory))

;;; CBOR Object Signing and Encryption (COSE)
;;; RFC8152
;;;
;;; COSE uses the following tags to identify the message type.
;;;
;;; 98 - cose-sign     COSE_Sign
;;; 18 - cose-sign1    COSE_Sign1
;;; 96 - cose-encrypt  COSE_Encrypt
;;; 16 - cose-encrypt0 COSE_Encrypt0
;;; 97 - cose-mac      COSE_Mac
;;; 17 - cose-mac0     COSE_Mac0
;;;
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
;;; COSE_Sign = [
;;;     Headers,
;;;     Payload : bstr / nil,
;;;     signatures : [+ COSE_Signature]
;;; ]
;;;
;;; COSE_Signature = [
;;;     Headers,
;;;     signature : bstr
;;; ]
;;;
;;; Sig_structure = [
;;;     context : "Signature" / "Signature1" / "CounterSignature",
;;;     body_protected : empty_or_serialized_map,
;;;     ? sign_protected : empty_or_serialized_map,
;;;     external_aad : bstr,
;;;     payload : bstr
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
;;;
;;; First, let's support cose-sign and cose-sign1

;;; These routines are generally written to accept decoded cbor (in
;;; the sexp-like format from cbor.rkt.  We can accept COSE_Sign1 and
;;; COSE_Sign with and without the initial cbor tag.  If present the
;;; CBOR tag must be correct for the contents, otherwise we try to
;;; detect it.

;;; Validate a COSE signature block.
(define (check-cose cbr
		    #:external [external #""])
  (match cbr
    [(struct cbor-tag (18 data)) ;; CBOR_Sign1
     (check-cose data
		 #:external external)]  ;; TODO: Make sure it is a sign1.
    [(struct cbor-tag (98 data)) ;; CBOR_Sign
     (check-cose data
		 #:external external)]  ;; TODO: Make sure it is a sign.
    [(list
       (? bytes? protected)
       (? hash? unprotected)
       (and payload (or (? bytes? _) (? cbor-null? _)))
       (? bytes? signature))
     (define prot-map (decode-protected protected))
     (when (cbor-null? payload)
       (error "TODO: Handle external payload"))
     (define to-be-signed
       (encode-cbor
	 (list "Signature1"
	       protected
	       external
	       payload)))
     ;; TODO: Validate the contents of the two maps.
     (printf "COSE_Sign1 found: ~a\n" prot-map)
     (dump to-be-signed)]

    [else (error "TODO" cbr)]))

;;; The protected map can be either a null, which results in an empty
;;; map, or actually a map.
(define (decode-protected item)
  (match item
    [(? cbor-null? _) (hasheq)]
    [(? bytes? item) (decode-cbor item)]))

;; Examples/rsa-pss-examples/rsa-pss-01.json
(define *sample1*
  (hex-string->bytes
      "D8628443A10300A054546869732069732074686520636F6E74656E742E818344\
A1013824A104581F6D65726961646F632E6272616E64796275636B407273612E\
6578616D706C65590100511AB7C07A4C9F1639FD955CDF17DB5FC9D7360E07E8\
DE8F835A6E443F56B816A842F5878707E9E4451F3EAEC39BBCB30C92EE07AC30\
F2C856A640D5BA5857F0A96135447F1A3FD207290AFC40A033FCACB6C031285E\
01FE4C9D4E528CA63C00C55109EA4F6E58232B5D9B7C5448CC4637C8EEAD7037\
CC71FDA4D1E83FB1FFA7294C744455785B9B9DBC7341826A6F90622533B9AA51\
998BEDBBD6D155869E189C4097B6E6EBBA2A5A6AA7E08AB8EDAB7021A567F36C\
715DE34CBF9048609503B7F70DA05EA6A6C7DF1301FB575ABE6F4DA8AAA93B5F\
A6267CA490F03BC90BB5705BB3398466C0AFE84AF91C0B752C6E1CAC149B07C2\
37988F47980F1301669C"))

;; For verification, the ToBeSigned of the above:
(define *to-be-signed-1*
  (hex-string->bytes
    "85695369676E617475726543A1030044A1013824405454686973206973207468\
6520636F6E74656E742E"))
