#lang racket/base

(require
  asn1
  crypto
  crypto/libcrypto
  crypto/sodium
  net/base64
  racket/match
  racket/pretty
  "cbor.rkt"
  "dump.rkt"
  )

;; This is specific to the EC private key
(define EC-PRIVATE
  (SEQUENCE
    [version INTEGER]
    [algorithm
      (SEQUENCE
	[algorithm OBJECT-IDENTIFIER]
	[parameter OBJECT-IDENTIFIER])]
    [key OCTET-STRING]))

(define (generate-rsa-key)
  (define key (generate-private-key 'rsa '((nbits 2048))))
  (define priv (pk-key->datum key 'RSAPrivateKey))
  (display "-----BEGIN RSA PRIVATE KEY-----\n")
  (display (base64-encode priv #"\n"))
  (display "-----END RSA PRIVATE KEY-----\n"))

(define (generate-ed25519-key)
  (define key (generate-private-key 'eddsa '((curve ed25519))))
  (define priv (pk-key->datum key 'OneAsymmetricKey))
  (define pub (pk-key->datum key 'SubjectPublicKeyInfo))
  (display "-----BEGIN ED25519 PRIVATE KEY-----\n")
  (display (base64-encode priv #"\n"))
  (display "-----END ED25519 PRIVATE KEY-----\n")
  (display "-----BEGIN PUBLIC KEY-----\n")
  (display (base64-encode pub #"\n"))
  (display "-----END PUBLIC KEY-----\n")
  
  ;; Lets show both.
  (display "=======private=======\n")
  (dump priv)
  (pretty-print (bytes->asn1/DER ANY priv))
  (newline)
  (display "=======public=======\n")
  (dump pub)
  (pretty-print (bytes->asn1/DER ANY pub))
  (newline)
  )

;;; Curves used in RFC8152:
;;;   prime256v1
;;;   secp384r1
;;;   secp521r1

(define (generate-ec-key)
  (define key (generate-private-key 'ec '((curve prime256v1))))
  (define priv (pk-key->datum key 'PrivateKeyInfo))
  (define pub (pk-key->datum key 'SubjectPublicKeyInfo))
  (display "-----BEGIN EC PRIVATE KEY-----\n")
  (display (base64-encode priv #"\n"))
  (display "-----END EC PRIVATE KEY-----\n")
  (display "-----BEGIN PUBLIC KEY-----\n")
  (display (base64-encode pub #"\n"))
  (display "-----END PUBLIC KEY-----\n")
  
  ;; Lets show both.
  (display "=======private=======\n")
  (dump priv)
  (let ([rkt (pk-key->datum key 'rkt-private)])
    (pretty-print rkt)
    (match rkt
      [(list 'ec 'private oid a b)
       (display "first:\n")
       (dump a)
       (display "second:\n")
       (dump (integer->bytes b))]))
  (let* ([dec1 (bytes->asn1/DER EC-PRIVATE priv)]
	 [subkey (hash-ref dec1 'key)]
	 [dec2 (bytes->asn1/DER ANY subkey)])
    (display "algorithm:\n")
    (pretty-print (hash-ref dec1 'algorithm))
    (display "key\n")
    (pretty-print dec2))
  ;; (pretty-print (bytes->asn1/DER EC-PRIVATE priv))
  (newline)
  (display "=======public=======\n")
  (dump pub)
  (pretty-print (pk-key->datum key 'rkt-public))
  (pretty-print (bytes->asn1/DER ANY pub))
  (newline)
  )

(module+ main

  (require racket/format
	   racket/list
	   racket/vector)

  ;; Setup crypto
  (crypto-factories (list libcrypto-factory sodium-factory))

  (define (help . args)
    (display "\nSpecify a command to run\n\n")
    (for ([p (in-list commands)])
      (display (format "    ~a - ~a~%"
		       (~a (first p) #:min-width 10 #:align 'right)
		       (second p)))))

  (define (gen . args)
    (generate-rsa-key))

  (define (gened . args)
    (generate-ed25519-key))

  (define (genec . args)
    (generate-ec-key))

  (define commands
    `(("help" "Show command help" ,help)
      ("gen" "Generate a key" ,gen)
      ("genec" "Generate an ed25519 key" ,genec)
      ("gened" "Generate an ed25519 key" ,gened)))

  (define (unknown)
    (display "*** Unknown subcommand")
    (newline))

  ;; Decode the command line.
  (let ([cmdline (current-command-line-arguments)])
    (cond [(zero? (vector-length cmdline))
	   (help)]
	  [(assoc (vector-ref cmdline 0) commands)
	   => (lambda (cmd)
		((third cmd) (vector-drop cmdline 1)))]
	  [else
	    (unknown)])))
