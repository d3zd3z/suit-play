#lang racket

;;; lexer/parser for CDDL.
(require parser-tools/lex
	 (prefix-in : parser-tools/lex-sre)
	 parser-tools/cfg-parser)

(define-tokens
  value-tokens (ID TAG6 MAJOR-AI OCCUR UINT NUMBER TEXT BYTES))

(define-empty-tokens
  terminals (SPACE NL POUND PLUS QUESTION COMMA COLON
		   CARRET AMP TILDE ARROW LPAREN RPAREN
		   LBRACE RBRACE LBRACKET RBRACKET LESS MORE
		   HYPHEN DOT3 DOT2 DOT SLASH EQUAL SLASH-EQUAL
		   SLASH-SLASH-EQUAL SLASH-SLASH EOF))

;;; The grammar makes S possibly empty, which isn't meaningful in a
;;; parser.  So, we'll require a "space" token to just return one
;;; item, and represent zero or more spaces in the grammar.
(define-lex-abbrevs
  ;; Whitespace.
  [lex:crlf (:or "\n" "\r\n")]
  [lex:comment (:: ";" (:* (:/ #\space #\U10fffd)) lex:crlf)]
  [lex:nl (:or lex:comment lex:crlf)]
  [lex:ws (:or #\space lex:nl)]
  [lex:s (:+ lex:ws)]

  ;; ID's a digits
  [lex:alpha (:/ #\u41 #\u5a #\u61 #\u7a)]
  [lex:ealpha (:or lex:alpha #\@ #\_ #\$)]
  [lex:digit (:/ #\0 #\9)]
  [lex:digit1 (:/ #\1 #\9)]
  [lex:hexdig (:or lex:digit (:/ #\A #\F))]
  [lex:bindig (:/ #\0 #\1)]
  [lex:id (:: lex:ealpha (:* (:: (:* (:or "-" "."))
				 (:or lex:ealpha lex:digit))))]
  ;; Strings and byte strings
  [lex:bsqual (:or "h" "b63")]
  [lex:sesc (:: "\\" (:/ #\u20 #\U10fffd))]
  [lex:bchar (:or (:/ #\u20 #\u26 #\u28 #\u5b #\u5d #\U10fffd)
		  lex:sesc lex:crlf)]
  [lex:schar (:or (:/ #\u20 #\u21 #\u23 #\u5b #\u5d #\U10fffd)
		  lex:sesc)]
  [lex:bytes (:: (:? lex:bsqual) #\u27 (:* lex:bchar) #\u27)]
  [lex:text (:: #\" (:* lex:schar) #\")]

  ;; Numbers
  [lex:uint (:or (:: (:? (:or "0x" "0b")) "0")
		 (:: lex:digit1 (:* lex:digit))
		 (:: "0x" (:+ lex:hexdig))
		 (:: "0b" (:+ lex:bindig)))]
  [lex:int (:: (:? "-") lex:uint)]
  [lex:exponent (:: (:or "+" "-") (:+ lex:digit))]
  [lex:fraction (:+ lex:digit)]
  [lex:hexfloat (:: "0x" (:+ lex:hexdig) "p" lex:exponent)]
  [lex:number (:or lex:hexfloat (:: lex:int
				    (:? lex:fraction)
				    (:? (:: "e" lex:exponent))))]
  ;; Note no space here.
  [lex:6tag (:: "#6" (:? (:: "." lex:uint)) "(")]

  ;; Occur is also non-space separated, so must be matched in the
  ;; lexer.  This replaces the STAR rule.
  [lex:occur (:: (:? lex:uint) "*" (:? lex:uint))]
  )

;; TODO: Numbers probably need to have the negative sign removed, or
;; the grammar can just programmatically reject negative occurences.

(define lex
  (lexer-src-pos
    ;; Whitespace is not returned, but skipped.  The only place in the
    ;; grammar that doesn't allow space is the #6.nn( form, which we
    ;; scan in the lexer as a unit.
    [lex:s  (return-without-pos (lex input-port))]
    [lex:id (token-ID lexeme)]
    [lex:nl 'NL]
    [lex:6tag (token-TAG6 lexeme)]
    [(:: "#" lex:digit (:? (:: "." lex:uint))) (token-MAJOR-AI lexeme)]
    [lex:uint  (token-UINT lexeme)]
    [lex:number  (token-NUMBER lexeme)]
    [lex:text (token-TEXT lexeme)]
    [lex:bytes (token-BYTES lexeme)]
    ["#"    'POUND]
    ; ["*"    'STAR]
    [lex:occur (token-OCCUR lexeme)]
    ["+"    'PLUS]
    ["?"    'QUESTION]
    [","    'COMMA]
    [":"    'COLON]
    ["^"    'CARRET]
    ["&"    'AMP]
    ["~"    'TILDE]
    ["=>"    'ARROW]
    ["("    'LPAREN]
    [")"    'RPAREN]
    ["{"    'LBRACE]
    ["}"    'RBRACE]
    ["["    'LBRACKET]
    ["]"    'RBRACKET]
    ["<"    'LESS]
    [">"    'MORE]
    ["-"    'HYPHEN]
    ["..."  'DOT3]
    [".."  'DOT2]
    ["."   'DOT]
    ["="   'EQUAL]
    ["/"   'SLASH]
    ["/="   'SLASH-EQUAL]
    ["//="   'SLASH-SLASH-EQUAL]
    ["//"   'SLASH-SLASH]
    [(eof) 'EOF]))

;; Parser for CDDL.  Note that the grammar isn't LALR(1), so we need
;; the backtracking cfg-parser.  Since writing grammars with arbitrary
;; backtracking is hard to debug, I wrote as much of this as possible
;; with LALR(1), and added a few productions that require
;; backtracking.
(define parse
  (cfg-parser
    (tokens terminals value-tokens)
    ;(start cddl)
    (start rule)
    (src-pos)
    (end EOF)
    (error (lambda args (printf "Parse error: ~v~%" args)))
    (grammar

      [rule
	(() '())
	;; This production is entirely contained in the second
	;; production, so we will have to distinguish these during
	;; semantic analysis.
	;; ((rule ID assign type) (cons (list 'type-rule $2 $4) $1))
	((rule ID assign grpent) (cons (list 'group-rule $2 $4) $1))
	]

      ;; Genericarg is always optional in the grammar
      [genericarg
	(() '())
	((LESS genericarg-rep MORE) $2)]
      [genericarg-rep
	((type1) (list $1))
	((genericarg-rep COMMA type1) (cons $3 $1))]

      ;; A type is one or more type1's separated by a single slash.
      [type
	((type1) (list $1))
	((type SLASH type1) (cons $3 $1))]

      ;; A type1 is a type 2, possibly separated by a rangeop and
      ;; another type2.
      [type1
	((type2) (list $1))
	((type2 rangeop type2) (list 'rangeop $1 $2 $3))
	((type2 ctlop type2) (list 'ctlop $1 $2 $3))]

      [type2
	((value) (list 'value $1))
	((ID genericarg) (list 'typename $1 $2))
	;; I think this gets priority over the parenthesized groups
	;; that are also possible below.
	((LPAREN type RPAREN) (list 'type-list $2))
	((TILDE ID genericarg) (list 'groupname $2 $3))
	((TAG6 type RPAREN) (list 'tag6 $2))
	((MAJOR-AI) (list 'major-ai $1))
	((POUND) (list 'any))
	((LBRACE group RBRACE) (list 'map $2))
	((LBRACKET group RBRACKET) (list 'array $2))
	((AMP LPAREN group RPAREN) (list 'amp-group $3))
	((AMP ID) (list 'amp-group-name $2))
	]

      [rangeop
	((DOT3) 'dot3)
	((DOT2) 'dot2)]

      [ctlop
	((DOT ID) $2)]

      ;; Group is one or more grpchoice separated by "//"
      [group
	((grpchoice) (list $1))
	((group SLASH-SLASH grpchoice) (cons $3 $1))]

      ;; The groupchoice is zero or more grpents (Yes this allows
      ;; things like "// //" as a valid group.
      [grpchoice
	(() '())
	((grpchoice grpent) (cons $2 $1))]

      ;; Since memberkey can be a 'type, we need to lift that rule out
      ;; of 'memberkey' and handle it explicitly here.
      ;; The entry starting with 'type' also must be lifted out of
      ;; here to avoid ambiguity with the top-level rule.
      [grpent
	((occur memberkey type optcom) (list 'memberkey $1 $2 $3))
	((occur ID genericarg optcom) (list 'genericname $1 $2 $3))
	((occur LPAREN group RPAREN optcom) (list 'nestgroup $1 $3)) ]

      ;; The occurences can be '*' possibly surrounded by digits (no
      ;; space), or '+' or '?'.
      [occur
	(() 'once)
	((OCCUR) (list 'genoccur $1))
	((PLUS) 'one-or-more)
	((QUESTION) 'optional)]

      [optcaret
	(() 'nocarret)
	((CARRET) 'withcaret)]

      [optcom
	(() #f)
	((COMMA) #f)]

      ;; The memberkey is an optional preceeding field.  The grammar
      ;; as written requires more than one lookahead, so we'll rewrite
      ;; the grammar as follows.
      [memberkey
	(() 'no-member-key)
	((type1 optcaret ARROW) (list 'arrow-key $1 $2))
	((ID COLON) (list 'idkey $1))
	((value COLON) (list 'value-key $1))]

      [assign
	((EQUAL) 'equal)
	((SLASH-EQUAL) 'slash-equal)
	((SLASH-SLASH-EQUAL) 'slash-slash-equal)]

      [value
	((UINT) (list 'number $1))
	((NUMBER) (list 'number $1))
	((TEXT) (list 'text $1))
	((BYTES) (list 'bytes $1))]
      )))

;;; Test the lexer with a string.
(define (stest text)
  (call-with-input-string
    text
    (lambda (in)
      (parse (lambda ()
	       (lex in))))))

;;; Test when given a filename
(define (ftest path)
  (call-with-input-file
    path
    (lambda (in)
      (port-count-lines! in)
      (parse (lambda ()
	       (lex in))))))
