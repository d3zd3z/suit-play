#lang racket/base

(require
  net/base64)

(provide read-pem
	 read-all-pem)

;;; Read a single PEM key from 'in' returning a list of two elements,
;;; the first being the name of the block, and the second being the
;;; binary data of the block.  Raises an exception on error, and
;;; returns eof-object if there is not key.
(define (read-pem [in (current-input-port)])
  (define pre (read-pem-barrier in))
  (if (eof-object? pre) pre
    (let-values ([(body post) (read-to-end in)])
      (cond [(eof-object? body)
	     (error "Unexpected eof reading PEM")]
	    [(bytes=? pre post)
	     (list pre (base64-decode body))]
	    [else (error "Section mismatch in PEM" pre post)]))))

;;; For convenience, read all of the pems in a file, until eof is
;;; reached, returning a list of the results.
(define (read-all-pem [in (current-input-port)])
  (let loop ([result '()])
    (let ([pem (read-pem in)])
      (if (eof-object? pem)
	(reverse result)
	(loop (cons pem result))))))

;;; Read a line, looking for a 'pem' barrier, returning the keywords
;;; from the barrier, eof-object on end of file, or raising an error
;;; otherwise.
(define (read-pem-barrier in)
  (define line (read-bytes-line in 'any))
  (cond [(eof-object? line) line]
	[(regexp-match #px"^-----BEGIN (.*)-----$" line)
	 => (lambda (group)
	      (cadr group))]
	[else (error "Invalid line in PEM")]))

(define (read-to-end in)
  (let loop ([result '()])
    (let ([line (read-bytes-line in 'any)])
      (cond [(eof-object? line)
	     (error "Early EOF reading PEM")]
	    [(regexp-match #px"^-----END (.*)-----$" line)
	     => (lambda (group)
		  (values (apply bytes-append (reverse result))
			  (cadr group)))]
	    [else
	      (loop (cons line result))]))))

