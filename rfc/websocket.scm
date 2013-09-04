
(library (rfc websocket)
  (export make-websocket-client
          websocket-wait-close
          websocket-connect
          websocket-close
          websocket-send
          websocket-ping
          websocket-send-bytevector
          websocket-send-string
          websocket-send)
  (import (rnrs)
          (sagittarius)
          (rnrs io ports)
          (math random)
          (math hash)
          (only (scheme base) bytevector-append)
          (sagittarius object)
          (sagittarius regex)
          (sagittarius threads)
          (only (sagittarius control) let1 rlet1 push!)
          (sagittarius socket)
          (rfc uri)
          (rfc tls)
          (rfc base64)
          (srfi :13 strings)
          (srfi :18 multithreading)
          (clos user))

  (define-syntax debug
    (syntax-rules ()
      ((_ expr)
       (call-with-values (lambda()expr)
         (lambda args
           (display "debug: " (current-error-port))
           (write args (current-error-port))
           (newline (current-error-port))
           (apply values args))))))

  (define-syntax if-let1
    (syntax-rules ()
      ((_ var expr act alt)
       (let1 var expr
         (if var act alt)))
      ((_ var expr act)
       (if-let1 var expr act #f))))

  (define-syntax until
    (syntax-rules ()
      ((_ expr body ...)
       (do () (expr) body ...))))

  (define (read-line-from-binary port)
    (call-with-values open-bytevector-output-port
      (lambda(out get)
        (let loop ((ch (get-u8 port)))
          (cond ((eqv? #x0d ch)
                 (if (eqv? (get-u8 port) #x0a)
                     (utf8->string (get))
                     (error 'read-line-from-binary "Invalid character")))
                ((eof-object? ch) (utf8->string (get)))
                (else (put-u8 out ch)
                      (loop (get-u8 port))))))))

  (define (assoc-ref alist obj :optional (default #f) (comp equal?))
    (if-let1 r (assoc obj alist comp)
      (cdr r)
      default))

  (define (put-u16 port num :optional (endian (endianness big)))
    (rlet1 v (make-bytevector 2)
      (bytevector-u16-set! v 0 num endian)
      (put-bytevector port v)))

  (define (put-u64 port num :optional (endian (endianness big)))
    (rlet1 v (make-bytevector 8)
      (bytevector-u64-set! v 0 num endian)
      (put-bytevector port v)))

  (define (get-u16 port :optional (endian (endianness big)))
    (let1 v (make-bytevector 2)
      (get-bytevector-n! port v 0 2)
      (bytevector-u16-ref v 0 endian)))

  (define (get-u64 port :optional (endian (endianness big)))
    (let1 v (make-bytevector 8)
      (get-bytevector-n! port v 0 8)
      (bytevector-u64-ref v 0 endian)))

  (define guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

  (define rand (secure-random Yarrow))

  (define (nonce)
    (utf8->string (base64-encode (read-random-bytes rand 16) :line-width #f)))

  (define (generate-mask) (read-random-bytes rand 4))

  (define (do-nothing . arg) #f)

  (define (sha1-digest-string str)
    (hash SHA-1 (string->utf8 str)))

  (define (accept-key key)
    (utf8->string
     (base64-encode
      (sha1-digest-string (string-append key guid))
      :line-width #f)))

  (define-class <websocket> ()
    ((on-message :init-keyword :on-message :init-value do-nothing)
     (on-open :init-keyword :on-open :init-value do-nothing)
     (on-error :init-keyword :on-error :init-value do-nothing)
     (on-close :init-keyword :on-close :init-value do-nothing)
     (socket :init-value #f)
     (receiver)
     (in)
     (out)
     (header)
     (wait-pong :init-value (make-condition-variable))
     (buffer :init-value '())
     (status :init-value 'closed)))

  (define (handshaked? self)
    (eq? 'open (slot-ref self 'status)))

  (define (websocket-wait-close self)
    (thread-join! (slot-ref self 'receiver)))

  (define (scheme->default-port scheme)
    (cond ((string=? scheme "ws") "80")
          ((string=? scheme "wss") "443")
          (else (error 'scheme->default-port "unsupported scheme:" scheme))))

  (define (url-split url)
    (receive (scheme user host port path query fragment)
        (uri-parse url)
      (let ((path (if path path "/"))
            (query (if query (string-append "?" query) "")))
        (values scheme
                user
                host
                (if port port (scheme->default-port scheme))
                (string-append path query)))))

  (define (request-line method path)
    (string-append method " " path " HTTP/1.1\r\n"))

  (define (header-field alst)
    (string-concatenate
     (fold-right
      (lambda(x s)
        (cons (string-append (->string (car x)) ": " (cdr x) "\r\n") s))
      '() alst)))

  (define (parse-status-line line)
    (let* ((r (regex "^HTTP/1.1 (\\d+) +(.+)$"))
           (m (looking-at r line)))
      (if m (values (m 1) (m 2))
          (error 'parse-status-line "Invalid status line:" line))))

  (define (request-header host key scheme origin)
    (header-field
     `((Host . ,host)
       (Upgrade . "websocket")
       (Connection . "Upgrade")
       (Sec-WebSocket-Key . ,key)
       (Origin . ,origin)
       (Sec-WebSocket-Version . "13"))))

  (define (parse-field line)
    (let* ((r (regex "^(\\S+): (.*)$"))
           (m (looking-at r line)))
      (if m
          (cons (m 1) (m 2))
          (error 'parse-field "Invalid header-field:" line))))

  (define (read-header port)
    (rlet1 r '()
      (do ((line (read-line-from-binary port) (read-line-from-binary port)))
          ((string-null? line))
        (push! r (parse-field line)))))

  (define (websocket-connect self url)
    (slot-set! self 'status 'connecting)
    (receive (scheme user host port path)
        (url-split url)
      (let* ((sock (if (equal? "wss" scheme)
                       (make-client-tls-socket host port)
                       (make-client-socket host port AF_INET)))
             (in (socket-input-port sock))
             (out (socket-output-port sock))
             (key (nonce))
             (origin (string-append
                      (cond 
                       ((string=? "ws" scheme) "http://")
                       ((string=? "wss" scheme) "https://"))
                      host)))
        (put-bytevector out
                        (string->utf8 (string-append
                                       (request-line "GET" path)
                                       (request-header host key scheme origin)
                                       "\r\n")))
        (flush-output-port out)
        (receive (code mes)
            (parse-status-line (read-line-from-binary in))
          (unless (equal? code "101")
            (error 'websocket-connect "fail connect")))
        (let1 header (read-header in)
          (if-let1 r (assoc-ref header "sec-websocket-origin" #f string-ci=?)
            (unless (string-ci=? r origin)
              (slot-set! self 'status 'closed)
              (slot-set! self 'socket #f)
              (error 'websocket-connect "origin doesn't match:" r)))
          (if-let1 r (assoc-ref header "Sec-WebSocket-Accept" #f string-ci=?)
            (string-ci=? r (accept-key key))
            (begin
              (slot-set! self 'status 'closed)
              (slot-set! self 'socket #f)
              (error 'websocket-connect "security digest doesn't match:" r)))
          (slot-set! self 'socket sock)
          (slot-set! self 'in in)
          (slot-set! self 'out out)
          (slot-set! self 'header header)
          (slot-set! self 'receiver
                     (make-thread
                      (lambda()
                        (guard (e (else ((slot-ref self 'on-error) e)))
                          (until (eq? (websocket-receive self) 'close)) #f))))
          (slot-set! self 'status 'open)
          (thread-start! (slot-ref self 'receiver))
          #t))))

  (define (websocket-close self)
    (unless (or (eq? 'open (slot-ref self 'status))
                (eq? 'closing (slot-ref self 'status)))
      (error 'websocket-close "websocket hasn't handshake yet."))
    (let1 port (slot-ref self 'out)
      (put-u8 port (fxior #x80 8))
      (put-u8 port #x80)
      (put-bytevector port (generate-mask))
      (flush-output-port port))
    (cond ((eq? 'open (slot-ref self 'status))
           (slot-set! self 'status 'closing))
          ((eq? 'closing (slot-ref self 'status))
           (slot-set! self 'status 'closed))))

  (define (websocket-pong self)
    (unless (handshaked? self)
      (error 'websocket-pong "websocket hasn't handshake yet."))
    (let1 port (slot-ref self 'out)
      (put-u8 port (fxior #x80 10))
      (put-u8 port #x80)
      (put-bytevector port (generate-mask))
      (flush-output-port port)))

  (define (websocket-ping self :optional (timeout 1000))
    (unless (handshaked? self)
      (error 'websocket-ping "websocket hasn't handshake yet."))
    (let1 port (slot-ref self 'out)
      (put-u8 port (fxior #x80 9))
      (put-u8 port #x80)
      (put-bytevector port (generate-mask))
      (flush-output-port port))
    (let ((mutex (make-mutex)))
      (mutex-lock! mutex)
      (mutex-unlock! mutex (slot-ref self 'wait-pong) timeout)))

  (define (write-payload-length self mask num)
    (let ((port (slot-ref self 'out))
          (maskbit (if mask #x80 0)))
      (cond ((<= 0 num 125)
             (put-u8 port (fxior num maskbit)))
            ((<= 126 num #x8000)
             (put-u8 port (fxior 126 maskbit))
             (put-u16 port num))
            ((<= #x10000 num #x4000000000000000)
             (put-u8 port (fxior 127 maskbit))
             (put-u64 port num))
            (else (error 'write-payload-length "Payload is too large")))
      (when mask (put-bytevector port mask))
      (flush-output-port port)))

  (define (apply-mask bvec mask)
    (let* ((len (bytevector-length bvec))
           (nvec (make-bytevector len)))
      (do ((i 0 (+ i 1)))
          ((= i len) nvec)
        (bytevector-u8-set! nvec i
                            (fxxor (bytevector-u8-ref bvec i)
                                   (bytevector-u8-ref mask (mod i 4)))))))

  (define (apply-mask! bvec mask)
    (let* ((len (bytevector-length bvec)))
      (do ((i 0 (+ i 1)))
          ((= i len) nvec)
        (bytevector-u8-set! bvec i
                            (fxxor (bytevector-u8-ref bvec i)
                                   (bytevector-u8-ref mask (mod i 4)))))))

  (define (websocket-send-bytevector self data)
    (unless (handshaked? self)
      (error 'websocket-send-binary "websocket hasn't handshake yet."))
    (let ((port (slot-ref self 'out))
          (len (bytevector-length data))
          (mask (genenerate-mask)))
      (put-u8 port (fxior #x80 2))
      (write-payload-length self mask len)
      (put-bytevector port (apply-mask data mask))
      (flush-output-port port)))

  (define-method websocket-send ((self <websocket>) (data <bytevector>))
    (websocket-send-bytevector self data))

  (define (websocket-send-string self data)
    (unless (handshaked? self)
      (error 'websocket-send-string "websocket hasn't handshake yet."))
    (let* ((port (slot-ref self 'out))
           (vec (string->utf8 data))
           (len (bytevector-length vec))
           (mask (generate-mask)))
      (put-u8 port (fxior #x80 1))
      (write-payload-length self mask len)
      (put-bytevector port (apply-mask vec mask))
      (flush-output-port port)))

  (define-method websocket-send ((self <websocket>) (data <string>))
    (websocket-send-string self data))

  (define (websocket-handler-text self payload fin)
    (cond ((and fin (null? (slot-ref self 'buffer)))
           ((slot-ref self 'on-message) (utf8->string payload)))
          ((and fin (not (null? (slot-ref self 'buffer))))
           (slot-set! self 'buffer
                      (cons payload (slot-ref self 'buffer)))
           ((slot-ref self 'on-message)
            (utf8->string
             (apply bytevector-append
                    (reverse (slot-ref self 'buffer)))))
           (slot-set! self 'buffer '()))
          ((not fin)
           (slot-set! self 'buffer
                      (cons payload (slot-ref self 'buffer))))))

  (define (websocket-handler-binary self payload fin)
    (cond ((and fin (null? (slot-ref self 'buffer)))
           ((slot-ref self 'on-message) payload))
          ((and fin (not (null? (slot-ref self 'buffer))))
           (slot-set! self 'buffer
                      (cons payload (slot-ref self 'buffer)))
           ((slot-ref self 'on-message)
            (apply bytevector-append (reverse (slot-ref self 'buffer))))
           (slot-set! self 'buffer '()))
          ((not fin)
           (slot-set! self 'buffer
                      (cons payload (slot-ref self 'buffer))))))

  (define (websocket-handler self op payload fin)
    (case op
      ((1) (websocket-handler-text self payload fin) 'text)
      ((2) (websocket-handler-binary self payload fin) 'binary)
      ((8) (if (eq? 'closing (slot-ref self 'status))
               (begin
                 (socket-close (slot-ref self 'socket))
                 (slot-set! self 'socket #f))
               (begin
                 (slot-set! self 'status 'closing)
                 (websocket-close self)
                 (socket-close (slot-ref self 'socket))
                 (slot-set! self 'socket #f)))
       ((slot-ref self 'on-close))
       'close)
      ((9) (websocket-pong self) 'ping)
      ((10)
       (condition-variable-signal! (slot-ref self 'wait-pong))
       'pong)
      (else "unknown opcode")))

  (define (websocket-receive self)
    (unless (or (eq? 'open (slot-ref self 'status))
                (eq? 'closing (slot-ref self 'status)))
      (error 'websocket-receive "websocket hasn't handshake yet."))
    (let* ((port (slot-ref self 'in))
           (b1 (get-u8 port))
           (fin (not (zero? (fxand #x80 b1))))
           (op (fxand #x0f b1))
           (b2 (get-u8 port))
           (mask-flag (not (zero? (fxand #x80 b2))))
           (plength (fxand #x7f b2)))
      (let* ((plength (case plength
                        ((126) (get-u16 port))
                        ((127) (get-u64 port))
                        (else plength)))
             (payload (make-bytevector plength)))
        (if mask-flag
            (let1 mask (make-bytevector 4)
              (get-bytevector-n! port mask 0 4)
              (get-bytevector-n! port payload 0 plength)
              (apply-mask! payload mask))
            (get-bytevector-n! port payload 0 plength))
        (websocket-handler self op payload fin))))

  (define (make-websocket-client
           :key (on-message do-nothing)
           (on-error do-nothing)
           (on-open do-nothing)
           (on-close do-nothing))
    (make <websocket>
      :on-message on-message
      :on-error on-error
      :on-open on-open
      :on-close on-close))

  )
