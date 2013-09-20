
(import (rfc websocket)
        (sagittarius threads)
        (rnrs exceptions (6))
        (rnrs))

(define websocket
  (make-websocket-client
   :on-message (lambda(x) (display "response: ") (display x) (newline))
   :on-error raise))

(websocket-connect websocket "wss://echo.websocket.org")
(websocket-send websocket "Hello, world.\n")
(display (websocket-ping websocket 1000))
(websocket-close websocket)
(websocket-wait-close websocket)