#lang racket

(require racket/format)

(provide dump)

;;;; Dumping byte strings in a format similar to "hexdump -C".

(define (dump buf)
  (define buf-len (bytes-length buf))
  (define (put-ascii a b)
    (display "  |")
    (for ([pos (in-range a b)])
      (let ([ch (integer->char (bytes-ref buf pos))])
	(display (if (or (char-graphic? ch) (char=? ch #\space))
		   ch
		   #\.))))
    (display "|")
    (newline))
  (for ([ch (in-bytes buf)]
	[index (in-naturals)])
    (cond
      [(zero? (bitwise-and index 15))
       (when (positive? index)
	 (put-ascii (- index 16) index))
       (display (~r index #:base 16 #:min-width 8 #:pad-string "0"))
       (display #\space)]
      [(zero? (bitwise-and index 7))
       (display #\space)])
    (display #\space)
    (display (~r ch #:base 16 #:min-width 2 #:pad-string "0")))
  (when (positive? buf-len)
    (let* ([pos (bitwise-and (sub1 buf-len) -16)]
	   [pad (- 16 (- buf-len pos))])
      (for ([i (in-range (- 16 (- buf-len pos)))])
	(display "   "))
      (when (> pad 7)
	(display #\space))
      (put-ascii pos buf-len))))

(define +test-buffer+
  (list->bytes (for/list ([i (in-range 256)]) i)))

(define (test-pattern)
  (for ([i (in-range 32)])
    (printf "Entry: ~a~%" i)
    (dump (list->bytes (for/list ([i (in-range i)]) i)))))
