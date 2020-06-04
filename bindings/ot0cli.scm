;;;* Stuff for the time being.

(define (debug l v)
  (let ((p  (current-error-port)))
    (display
     (call-with-output-string
      (lambda (p)
        (display (current-thread) p)
        (display " " p)
        (display l p)
        (display ": " p)
        (write v p)
        (newline p)))
     p)
    ((cond-expand (gambit force-output) (chicken flush-output)) p)
    v))

(define (NYI . args)
  ;; A textual upper case marker for thing in planning phase.  A three
  ;; letter acronym and a warning when used as procedure.  More use
  ;; cases might be added withouth harm.
  (println "NYI (Not Yet Implemented) " args))

(include "/home/u/build/ln/cmd/apps/cmd/observable-notational-conventions.scm")

(define (%add-to-lset obj lst #!optional (cmp eq?))
  (if (member obj lst cmp) lst (cons obj lst)))

(define (remove1 obj lst #!optional (cmp eq?))
  (if (member obj lst cmp) (remove (lambda (x) (cmp x obj)) lst) lst))

(include "/home/u/build/ln/modules/socks/socks.scm")

;;;** Utilitarian Garbage :Notational Conventions:

;;;*** Well Known Procedures

(define (%string->well-known-procedure x kind #!optional (isa? procedure?))
  (let rec ((x x))
    (match
     x
     ((or "socks-server" "socks") (lambda () (socks-server kind)))
     ((? string? str)
      (let ((val (eval (string->symbol str))))
        (cond
         ((isa? val) val)
         (else (error "spec did not parse as well known procedure" str val isa?))))))))

;;;*** Test Framework
(include "test-environment.scm")

(define current-log-port (make-parameter (current-output-port)))
(define (ot0-log msg . more) (println port: (current-log-port) msg more))

;;;*** Sockets and Network

(define (is-ip4-local? ip)
  (and (eqv? (u8vector-length ip) 4)
       (eqv? (u8vector-ref ip 0) 192)
       (eqv? (u8vector-ref ip 1) 168)
       (eqv? (u8vector-ref ip 2) 43)))

(define socks-forward-addr (make-parameter "127.0.0.1:9050"))

(define (ot0cli-socks-connect name addr port)
  (define (socks-forward? x) (socks-forward-addr))
  (define (looks-like-ot0-ad-hoc? addr)
    (and (> (string-length addr) 2)
         (member (substring addr 0 2) '("FC" "fc"))))
  (define (looks-like-loopback? addr)
    (and (> (string-length addr) 3)
         (or (member (substring addr 0 2) '("127" "fc"))
             (string=? addr "localhost"))))
  (ot0-log "SOCKS " name " " addr " " port)
  (match
   addr
   ((? looks-like-ot0-ad-hoc?) 'lwip)
   ((? looks-like-loopback?) #f)
   ((? socks-forward?) (open-socks-tcp-client (socks-forward-addr) addr port))
   (_ (open-tcp-client `(address: ,addr port: ,port)))))

(on-socks-connect (lambda (key addr port) (ot0cli-socks-connect key addr port)))

(define crude-ip+port-split
  (let ((splt (rx "]?:[[:numeric:]]+$"))
        (brace (rx "^\\[")))
    (lambda (spec)
      (let ((left (rx-split splt spec)))
        (if (pair? left)
            (let* ((raw (car left))
                   (has-brace (rx~ brace raw))
                   (l1 (string-length raw))
                  (left (if has-brace (substring raw 1 l1) raw)))
              (values
               (or (lwip-string->ip6-address left) (lwip-string->ip4-address left))
               (string->number (substring spec (+ l1 (if has-brace 2 1)) (string-length spec)))))
            (values #f #f))))))
(define (ot0cli-connect name spec)
  (ot0-log "FORWARD " name " " spec)
  (receive
   (addr port) (crude-ip+port-split spec)
   (cond
    ((and addr port (eq? (u8vector-ref addr 0) #xfc))
     (open-lwip-tcp-client-connection addr port))
    ((or (equal? addr lwip-ip4addr-loopback) (equal? addr lwip-ip6addr-loopback))
     (open-tcp-client spec))
    (else
     (if (socks-forward-addr)
         (open-socks-tcp-client (socks-forward-addr) addr port)
         (open-tcp-client spec))))))

;;;*** We need some file locking

(c-declare "
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
")
(define open2/ro (c-lambda (char-string) int "___return(open(___arg1, 0, O_RDONLY));"))
(define open2 (c-lambda (char-string) int "___return(open(___arg1, 0));"))
(define flock-try-lock! (c-lambda (int) bool "___return(flock(___arg1, LOCK_EX|LOCK_NB) == 0);"))
;;(define flock-lock! (c-lambda (int) bool "___return(flock());"))
;; (define flock-unlock! (c-lambda (int) bool "___return(flock());"))

;;;* Thread safe udp

(define (open-udp2 spec)
  (let ((port (open-udp spec)))
    (and
     port
     (let ((g (make-mutex spec)))
       (mutex-specific-set! g port)
       g))))

(define (wire-udp-portnr-to-port! nr port)
  (wire!
   nr
   ;; FIXME: `critical` MUST run BEFORE `sequence`!
   ;;
   ;;critical: (lambda (o) (if o (close-port (port))))
   sequence:
   (lambda (o n)
     ;; (println "switching from " o " to " n)
     (if o (close-port (port)))
     (and n (port (open-udp2 n))))))

(define-pin udp-services
  initial: '()
  name: "list of running UPD services")

(define (add-udp-service! conn)
  (kick
   (let ((old (udp-services)))
     (unless (memq conn old) (udp-services (cons conn old))))))

(define (%%remove-udp-service! conn)
  (kick
   (let ((old (udp-services)))
     (when (memq conn old)
           (udp-services (fold (lambda (e r) (if (eq? e conn) r (cons e r))) '() old))))))

(define (udp-wire-service ump-ref receiver)
  (define (endless)
    (add-udp-service! ump-ref)
    (do ((ump (ump-ref) (ump-ref)))
        ((not ump) (%%remove-udp-service! ump-ref))
      (let* ((port (mutex-specific ump))
             (data (read port))
             (from (udp-source-socket-info port)))
        (receiver data from))))
  (and ump-ref (box endless)))

(define (ot0cli-udp-send-message ump-ref to port data #!optional (start 0) (end (u8vector-length data)))
  (define ump? mutex?)
  (define (udp-send-message* to port data start end out)
    (udp-destination-set! out to port)
    (udp-write-subu8vector data start end out))
  (let ((ump (and (procedure? ump-ref) (ump-ref))))
    (and (ump? ump)
         (let* ((out (begin (mutex-lock! ump)
                            (mutex-specific ump)))
                (result (udp-send-message* to port data start end out)))
           (mutex-unlock! ump)
           result))))

;;;* OT0

(define-pin ot0-online
  initial: #f
  pred: boolean?
  filter: (lambda (o n) (if (boolean? n) n (eq? 'ONLINE n)))
  name: "OT0 is online (set from on-ot0-event)")

(define ot0-up (PIN)) ;; not yet used

(include "ot0use.scm")

;; (ot0cli-wire-address-add-filter! is-ip4-local?)

;;;** The Command Line Tool

(define (with-output-to-secret-file fn thunk)
  (with-output-to-file `(path: ,fn, permissions: #o400) thunk))

(define (with-output-to-public-file fn thunk)
  (with-output-to-file `(path: ,fn, permissions: #o644) thunk))

(define-pin ot0-context
  initial: #f
  filter: (lambda (o n)
            (if o o (and (string? n) n)))
  name: "context directory")
(define-pin ot0-context-kind)
(define-pin ot0-state-file
  initial: (lambda (type id) (error "ot0-state-file: not yet initialized"))
  name: "procedure to name a particular ot0 state in ot0-context")
(wire! ot0-context post: (lambda () (ot0-state-file (ot0-state-file-generator (ot0-context-kind) (ot0-context)))))
(define-pin ot0cli-locked #f)

(define-pin ot0cli-origin
  initial: #f
  pred: (lambda (x) (or (not x) (u8vector? x)))
  name: "the 'origin' within context directory - in r/w context written upon assignment")
(wire!
 (list ot0-state-file ot0cli-locked) post:
 (lambda ()
   (let ((fn ((ot0-state-file) 3 0)))
     (ot0cli-origin (read-file-as-u8vector fn))
     (if (ot0cli-locked) (wire! ot0cli-origin fn ot0cli-origin)))))

(define (ot0-init-context! dir)
  (define (init-context! dir)
    (kick/sync (ot0-context dir) (ot0-context-kind 0))
    (let ((id (ot0-generate-id))
          (fnp ((ot0-state-file) 1 0))
          (fns ((ot0-state-file) 2 0)))
      (with-output-to-secret-file fns (lambda () (display (ot0-id->string id #t))))
      (with-output-to-public-file fnp (lambda () (display (ot0-id->string id))))))
  (define (create-context! dir)
    (define (%*create-subdirs! dir)
      ;; FIXME: das geht besser
      (create-directory `(path: ,(string-append dir "/junction") permissions: #o700))
      (create-directory `(path: ,(string-append dir "/unit") permissions: #o700))
      (create-directory `(path: ,(string-append dir "/network") permissions: #o700)))
    (create-directory `(path: ,dir permissions: #o700))
    (with-output-to-file `(path: ,(string-append dir "/lock") permissions: #o644) (lambda () #t))
    (%*create-subdirs! dir)
    (init-context! dir))
  (if (not (file-exists? dir)) (create-context! dir)
      (let ((fi (file-info dir)))
        (cond
         ((not (eq? (file-info-type fi) 'directory))
          (error "ot0-init-context!: file exists and is not a directory" dir))
         ((null? (directory-files `(path: ,dir ignore-hidden: dot-and-dot-dot)))
          (init-context! dir))
         (else (error "ot0-init-context!: directory is not empty" dir))))))

(define (ot0-global-context-set! kind dir exclusive)
  (define (lockit! . args)
    (let ((fd (let ((new-style ((ot0-state-file) 0 0)))
                (if new-style
                    (open2/ro new-style) ;; dedicated lock file
                    ;; lock secret key
                    (open2 ((ot0-state-file) 1 0))))))
      (unless
       (flock-try-lock! fd)
       (display "ot0-context: failed to lock" (current-error-port))
       (exit 1))
      #;Kicking: (lambda () (ot0cli-locked fd))))
  (if exclusive (wire! ot0-state-file critical: lockit!))
  (kick/sync
   (ot0-context dir)
   (ot0-context-kind
    (match
     kind
     ((? fixnum?) kind)
     (_ (error "while setting context: illegal kind:" kind))))))

(define-pin ot0cli-server) ;; boolean (so far) indicating server started
(define-pin ot0cli-ot0-networks
  initial: '()
  name: "list of networks joined")

(define (hexstr id digits)
  (let ((effective (number->string id 16)))
    (string-append (make-string (- digits (string-length effective)) #\0) effective)))

(define (ot0-server-start!
         port-settings #!key
         (background-period 0.5)
         (local-interfaces '())
         (join '()))
  (cond
   ((ot0-up?) (error (debug 'error "ot0-server already running")))
   ((not (ot0-context)) (error (debug 'error "context directory not set"))))
  (let ((result (PIN))
        (udp (open-udp port-settings)))
    (define (rcv<-udp port)
      (lambda ()
        (let* ((data (read port))
               (src (udp-source-socket-info port))
               (from (internetX-address->socket-address
                      (socket-info-address src) (socket-info-port-number src))))
          (values data from))))
    (receive
     (get put) (ot0-make-default-state-handlers (ot0-state-file))
     (on-ot0-state-get get)
     (if (ot0cli-locked)
         (on-ot0-state-put put)))
    (ot0-node-init! udp (rcv<-udp udp) background-period: background-period)
    (for-each ot0-add-local-interface-address! local-interfaces)
    (let ((origin (ot0cli-origin)))
      (and origin (ot0-vertex-contact-all-edges! (u8vector->ot0-vertex origin))))
    (let ((joined
           (fold
            (lambda (nw r) (if (ot0-join nw) (cons nw r) r))
            '() join)))
      (kick (ot0cli-server #t) (ot0cli-ot0-networks joined)))))

(define-sense* lwIP
  initial: #t
  pred: boolean?
  filter: (lambda (old new) (or old (match new ((or #f 'no "no" "n" "N" "NO") #f) (_ #t))))
  name: "lwIP enabled (can not (yet) be undone)")

(wire!
 (list lwIP ot0cli-server ot0cli-ot0-networks)
 sequence:
 (lambda (ol nl os ns on nn)
   (define (cfg-add! nw)
     (ot0cli-register-ot0adhoc-address network-id: nw unit-id: (ot0-address)))
   (cond
    ((and nl ns ;; if lwIP or OT0 come up after ot0cli-ot0-networks: add all
          (not (and ol os))
          (pair? nn))
     (for-each cfg-add! nn))
    ((and nl ns (pair? nn)) ;; otherwise add newcomers only
     (for-each
      (lambda (nw) (unless (member nw on) (cfg-add! nw)))
      nn)))))

(define (handle-replloop-exception e)
  (cond
   ((unbound-global-exception? e)
    (println "Unbound variable " (unbound-global-exception-variable e)))
   (else (##default-display-exception e (current-error-port))))
  #!void)

(define (replloop) ;; interactive read-evaluate-print-loop
  (with-exception-catcher handle-replloop-exception (lambda () (##repl-debug #f #t)))
  (replloop))

(define **program-file-name** (car (command-line)))

(define-values
  ;; Handling END marker.  May be set once only.
  (end-marker? set-end-marker! end-marker-source)
  (let ((default "[,:.;]")
        (source #f)
        (current #f))
    (values
     (lambda (str)
       (unless current (set! current (rx default)))
       (and (string? str) (rx~=? current str)))
     (lambda (str)
       (if current (error "PERIOD marker already defined upon attempt define" str))
       (if (rx~=? (rx "^-:.*"))
           (error "Attempt to set PERIOD marker: options beginning with \"-:\" are reserved." str))
       (set! source str)
       (set! current (rx str)))
     (lambda () (or source default)))))
(define (not-end-marker? x) (not (end-marker? x)))
(define !END? not-end-marker?)
(define PERIOD? end-marker?)

(define (cont-with-list-to-end-marker-and-rest args cont)
  (let loop ((tluser '()) (more args))
    (match
     more
     ((first . more)
      (match
       first
       ((? end-marker?) (cont (reverse tluser) more)) ;; shift and cont(inue)
       ;; collect and loop
       (_ (loop (cons first tluser) more))))
     ;; cont(inue) without shift
     (more (cont (reverse tluser) more)))))

;; Close your eyes!  These two macro create the build in command line
;; help.

(define-macro (match-lambda/doc doc . clauses)
  ;; TBD:performance: replace trailing '(sym ...) with '( . ,sym) but
  ;; still print the original code (and remove leading and traileing
  ;; parenthesis).
  (let* ((doc?
          (match-lambda
           ((? string?) #t)
           (((? string?) . more) #t)
           (_ #f)))
         (match/doc:plain-clauses
          (map
           (match-lambda
            ((m e) `(,m ,e))
            ((m '=> e) `(,m => ,e))
            ((m (? doc?) e) `(,m ,e))
            ((m (? doc?) '=> e) `(,m => ,e)))
           clauses))
        (match/doc:docstring
         (with-output-to-string
           (lambda ()
             (define pp-match
               (match-lambda
                (() (display "NONE"))
                ((syntax-pattern) (begin (write syntax-pattern) (newline)))
                ((syntax-pattern . rest)
                 (begin
                   (write syntax-pattern)
                   (unless (null? rest) (display " ") (pp-match rest))))))
             (define (pp/doc1 m str)
               (unless (equal? str "")
                       (if (null? m)
                           (display "NONE")
                           (pp-match m))
                       (display "\t") (display str) (newline)))
             (define (pp/doc m doku)
               (match
                doku
                ((? string? str) (pp/doc1 m str))
                (((? string? str) . more) (pp/doc1 m str))
                (_ #f)))
             (do ((clauses clauses (cdr clauses)))
                 ((or (null? clauses)
                      (match (caar clauses)
                             (('(? key-help?) . more) #t)
                             ('otherwise #t)
                             (_ #f))))
               (match
                (car clauses)
                ((m e) (pp m (current-output-port)))
                ((m '=> e) (pp m (current-output-port)))
                ((m (? doc? x) e) (pp/doc m x))
                ((m (? doc? x) '=> e) (pp/doc m x)))
               clauses))))
        (subdoc (gensym))
        (docstring (gensym)))
    `(let* ((,subdoc (box '()))
            (,(match doc ((sym . more) sym) (_ doc))
             (let ((,docstring ,match/doc:docstring))
               (lambda args
                 (display ,docstring)
                 (match
                  args
                  (() #t)
                  ((key . more)
                   (for-each (match-lambda ((k v) (v key))) (unbox ,subdoc))))
                 (newline)
                 #;(exit 0)))))
       ,@(match
          doc
          ((sym key) `((set-box! ,subdoc (cons (list ,key ,sym) (unbox ,subdoc)))))
          (_ '()))
       (match-lambda . ,match/doc:plain-clauses))))

(define-macro (match-lambda/doc+ doc fail loc msg . clauses)
  (cond
   ((and loc msg)
    `(match-lambda/doc
      ,doc
      ,@clauses
      (((? key-help?) . more) (,doc))
      (otherwise (,fail ,loc ,msg otherwise))))
   ((not loc) `(match-lambda/doc ,doc ,@clauses))
   ((not msg)
    `(match-lambda/doc
      ,doc
      ,@clauses
      (((? key-help?) . more) (,doc))
      ,loc))
   (else (error "match-lambda/doc+: macro failed badly" loc msg))))

;;;** Commands

(define (ot0cli-ot0-display-status! . unused)
  (println "Here:\n public:\n " (ot0-node-status) )
  (println " #x" (hexstr (ot0-address) 10) " " (ot0-address) " in nw "
           (map
            (lambda (nwid)
              (string-append "#x" (hexstr nwid 16) " " (number->string nwid) " "))
            (ot0cli-ot0-networks))
           ".")
  (ot0cli-display-nifs)
  (println "Peer units:")
  (pp (ot0-peers-info) (current-output-port))
  (ot0cli-wire-statistics-print!))

(define-pin ot0cli-control-server-port
  initial: #f
  filter:
  (lambda (old new)
    (match new
           (#f #f)
           ((? fixnum? positive?)
            `(local-port-number: ,new local-address: "127.0.0.1"))))
  name: "port for control server")
(define (ot0cli-control-server)
  (parameterize
   ((current-error-port (current-output-port)))
   (let ((expr (read)))
     (unless
      (eof-object? expr)
      (with-exception-catcher
       handle-replloop-exception
       (lambda () (ot0cli-1 expr (lambda () #t))))))))
(wire!
 ot0cli-control-server-port
 sequence:
 (lambda (old new)
   (if old (tcp-service-unregister! old))
   (if new (tcp-service-register! new ot0cli-control-server))))

(define (%ot0cli-client-commands! args key-help? continue! fail)
  (define (%common* type unit reference msg cont more)
    (let ((unit (call-with-input-string unit read))
          (reference (call-with-input-string reference read)))
      (ot0-send! type unit reference (object->u8vector msg)))
    (cont more))
  (define *ot0client-commands!
    (match-lambda/doc+
     help fail
     ;; (more "" (continue! more)) #f
     "client command did not parse" "-s"
     (((or "q" "query" "get") UNIT NUMBER MSG more ...)
      "Query UNIT with reference NUMBER (a 62 bit natural) and MSG."
      (%common* 'query UNIT NUMBER MSG *ot0client-commands! more))
     (((or "r" "request" "p" "post") UNIT NUMBER MSG more ...)
      "Post request to UNIT with reference NUMBER (a 62 bit natural) and MSG."
      (%common* 'post UNIT NUMBER MSG *ot0client-commands! more))
     (((or "d" "data" "a" "answer") UNIT NUMBER MSG more ...)
      "Answer with MSG as result data to UNIT with reference NUMBER (a 62 bit natural)."
      (%common* 'result UNIT NUMBER MSG *ot0client-commands! more))
     (((or "e" "error" "c" "condition") UNIT NUMBER MSG more ...)
      "Inform UNIT with reference to NUMBER (a 62 bit natural) about exceptional error condition MSG."
      (%common* 'condition UNIT NUMBER MSG *ot0client-commands! more))
     (("send" (and (or "q" "query" "r" "request" "d" "data" "c" "condition") TYPE) UNIT NUMBER MSG more ...)
      "Send MSG with TYPE and reference NUMBER (a 62 bit natural) to UNIT"
      (let ((type (match TYPE
                         ((or "q" "query") 'query)
                         ((or "r" "request") 'post)
                         ((or "d" "data") 'data)
                         ((or "c" "condition") 'error))))
        (%common* 'condition UNIT NUMBER MSG *ot0client-commands! more)))
     (((? PERIOD?) more ...) "leave \"-send\" mode and continue with more..." (continue! more))
     (() "" (continue! '()))))
  (*ot0client-commands! args))

(define (ot0cli-make-connect-service key dest)
  (lambda ()
    (let ((conn (ot0cli-connect key dest)))
      (ports-connect! conn conn (current-input-port) (current-output-port))
      (close-port conn))))

(define (ot0cli-services! args key-help? continue! fail)
  (define *ot0commands!
    (match-lambda/doc+
     help fail (more "" (continue! more)) #f
     (("start" PORT-SPEC more ...)
      "start ot0 service with PORT-SPEC optional ot0 commands and more"
      (let ((port-settings (call-with-input-string PORT-SPEC read)))
        (ot0-server-start! port-settings)
        (*ot0commands! more)))
     (((or "local-address:" "lip:") IPADDR more ...) "use also local IPADDR"
      (let ((addr (or (string->socket-address IPADDR)
                      (error "IP address did not parse" IPADDR))))
        (ot0-add-local-interface-address! addr)
        (*ot0commands! more)))
     (("join:" NETWORK more ...) "connect to NETWORK"
      (let ((nwid (call-with-input-string NETWORK read)))
        (ot0-join nwid)
        (kick (ot0cli-ot0-networks (%add-to-lset nwid (ot0cli-ot0-networks))))
        (*ot0commands! more)))
     (("via:" JUNCTION more ...) "may use JUNCTION"
      (let ((ndid (call-with-input-string JUNCTION read)))
        (ot0-orbit ndid)
        (*ot0commands! more)))
     (("contact:" UNIT ADDRESS more ...) "try to contact UNIT at ADDRESS"
      (let ((addr (string->socket-address ADDRESS)))
        (ot0-contact-peer UNIT addr)
        (*ot0commands! more)))
     (("leave:" NETWORK more ...) "leave to NETWORK"
      (let ((nwid (call-with-input-string NETWORK read)))
        (ot0-leave nwid)
        (*ot0commands! more)))
     (((or "avoid:" "forget:") JUNCTION more ...) "avoid JUNCTION"
      (let ((ndid (call-with-input-string JUNCTION read)))
        (ot0-deorbit ndid)
        (*ot0commands! more)))
     (("send:" (and (or "q" "query" "r" "request" "d" "data" "c" "condition") TYPE) UNIT NUMBER MSG more ...)
      "Send MSG with TYPE and reference NUMBER (a 62 bit natural) to UNIT"
      (let ((unit (call-with-input-string UNIT read))
            (type (match TYPE
                         ((or "q" "query") 'query)
                         ((or "r" "request") 'post)
                         ((or "d" "data") 'data)
                         ((or "c" "condition") 'error)))
            (reference (call-with-input-string NUMBER read)))
        (ot0-send! type unit reference (object->u8vector MSG))
        (*ot0commands! more)))
     (("status" more ...) "print status information"
      (begin (ot0cli-ot0-display-status!) (*ot0commands! more)))))
  (define *services!
    (match-lambda/doc+
     help fail "service setting did not parse" "-service"
     (("tcp" "register" PORT-SPEC SERVICE more ...)
      "register TCP \"SERVICE\" {socks-server, ...} on PORT-SPEC"
      (let ((port-settings (call-with-input-string PORT-SPEC read))
            (service-procedure (%string->well-known-procedure SERVICE 'tcp)))
        (tcp-service-register! port-settings service-procedure)
        (continue! more)))
     (("tcp" "forward" PORT-SPEC DEST more ...)
      "register TCP PORT-SPEC as forward to DEST
\t\tHint: To provide IP address with port be sure to SPEC is enclosed in double quotes."
      (let ((port-settings (call-with-input-string PORT-SPEC read)))
        (tcp-service-register! port-settings (ot0cli-make-connect-service 'tcp-forward DEST))
        (continue! more)))
     (("udp" "register" PORT-SPEC SERVICE more ...)
      "register UDP \"service\" {ot0} on {port-spec}"
      (let ((port-settings (call-with-input-string PORT-SPEC read)))
        (match
         SERVICE
         ((or "ot0" "ot0service") (ot0-server-start! port-settings))
         (else
          (let ((service-procedure (%string->well-known-procedure SERVICE 'udp))
                (reference (make-pin)))
            (unless (procedure? service-procedure) (error "illegal service" SERVICE))
            (wire! reference post: (udp-wire-service reference service-procedure)) )))
        (continue! more)))
     (("vpn" "tcp" "register" PORT-SPEC SERVICE OPTIONS...PERIOD ...)
      "register TCP \"SERVICE\" on PORT-SPEC"
      (let ((port-settings (call-with-input-string PORT-SPEC read))
            (service-procedure (%string->well-known-procedure SERVICE 'vpn)))
        (define (confirm options more)
          (lwip-tcp-service-register! port-settings service-procedure)
          (continue! more))
        (cont-with-list-to-end-marker-and-rest OPTIONS...PERIOD confirm)))
     (("vpn" "tcp" "forward" PORT-SPEC DEST more ...)
      "on vpn register PORT-SPEC as forwarded to DEST
\t\tHint: To provide IP address with port be sure to SPEC is enclosed in double quotes."
      (let ((port-settings (call-with-input-string PORT-SPEC read)))
        (lwip-tcp-service-register! port-settings (ot0cli-make-connect-service 'vpn DEST))
        (continue! more)))
     (("control" PORT OPTIONS..PERIOD ...)
      "start control server on loopback PORT
\t\tBEWARE DANGER: currently *unlimited* and *unauthenticated* (i.e., just good for debugging)"
      (let ((port (string->number PORT)))
        (define (confirm options more)
          (unless port (error "not a valid port number" PORT))
          (kick (ot0cli-control-server-port port))
          (continue! more))
        (if (ot0cli-control-server-port)
            (error "control server already on port" (ot0cli-control-server-port)))
        (cont-with-list-to-end-marker-and-rest OPTIONS..PERIOD confirm)))
     (("ot0" more ...) "ot0 commands and more" (*ot0commands! more))))
  (*services! args))

(define (ot0cli-admin! args key-help? continue! fail)
  (define *commands!
    (match-lambda/doc+
     help fail (more "" (continue! more)) #f
     (((or "origin:=" "set-origin:") FILE more ...) "copy FILE to origin"
      (let ((data (read-file-as-u8vector FILE)))
        (if data (kick (ot0cli-origin data)))
        (*commands! more)))
     (("lwip:" (and "on" enable) more ...) "enable lwip (once)"
      (begin (kick (lwIP #t)) (*commands! more)))))
  (*commands! args))

(define (set-debug! args key-help? continue! fail)
  (define *set-debug!
    (match-lambda/doc+
     help fail "debug setting did not parse" "-d"
     (((or "trace" "t") (and (or "trigger" "bgexn" "wire" "ot0") key) more ...) "trace on key
\tbgexn:  report exception terminating background threads
\ttrigger: report execution phases
\twire: log network
\tot0: log vpn"
      (begin
        (match
         key
         ("wire" (ot0cli-ot0-wire-trace-toggle!))
         ("ot0" (ot0cli-ot0-trace-toggle!))
         ("bgexn" ($async-exceptions 'trace))
         ("trigger" ($debug-trace-triggers #t)))
        (continue! more)))
     (("-:da9" more ...) "raise background exception in primordial thread"
      ;; This is just documented here, but actually handled by gambit
      (continue! more))
     (("tests") "run compiled in command line tests (deprecated, will be removed)"
      (begin (for-each ot0cli-1 (ot0cli-tests)) (continue! more)))
     (("stm-retry-limit" number more ...) "set STM retry limit to number"
      (let ((n (string->number number)))
        (unless (and n (>= n 0)) (error "illegal value" number))
        ($stm-retry-limit n) (continue! more)))))
  (*set-debug! args))

(define ##escape-from-ot0cli#wait-for-services
  (let ((mux (make-mutex '##ot0cli#wait-for-services)))
    (mutex-lock! mux)
    (lambda () (mutex-lock! mux))))

(define s)
(define (ot0cli-print-status #!optional more)
  (define (print-debug-status*)
    (println "kick style: " ($kick-style)))
  (define (print-status*)
    (println "PERIOD token (regex): " (end-marker-source))
    (println "context directory: " (ot0-context) " kind: " (ot0-context-kind))
    (print-debug-status*)
    (if (ot0cli-server) (ot0cli-ot0-display-status!)))
  (print-status*))
(set! s ot0cli-print-status)

;;;** Command Line Parser

(define (ot0cli-1 args #!optional (finally (lambda () #t)))
  (define %wait-for-services ##escape-from-ot0cli#wait-for-services)
  (define key-help? (lambda (s) (and (member s '("-h" "-help" "--help")) #t)))
  (define refuse-help-key-as-file-name
    (match-lambda
     ((? key-help? key)
      (error "cowardly refusing to create files/diretories matching the key for HELP" key))
     (file-name file-name)))
  (define (cmd-line-parse-error) "command did not parse")
  (define (read-file-as-u8vector-or-fail key file)
    (or (read-file-as-u8vector file) (error "could not read file" key file)))
  (define (error-with-unhandled-params msg location rest)
    (error msg **program-file-name** location rest))
  (define (using-context! dir cont more)
    (receive
     (kind dir more)
     (match (cons dir more)
            (("kind:" key dir . more) (values (string->number key) dir more))
            (_ (values 0 dir more)))
     (ot0-global-context-set! kind dir #t)
     (cont more))
    (exit 0))
  (define (print-status cont cmds)
    (match
     cmds
     (more (begin (ot0cli-print-status) (cont more)))))
  (define c25519!
    (match-lambda/doc+
     help error-with-unhandled-params (cmd-line-parse-error) "-c25519"
     (("make-kp" FILE) "create key pair in FILE"
      ;; TODO: write to out-file <signature>.FILE where <signature>
      ;; covers the public key such that we can proove consistency
      ;; wrt. FILE's name.
      (let* ((u8 (begin ;; DO NOT even provide an enforcement switch!
                   (when (file-exists? FILE)
                         (error "error file for keypair already exists" FILE))
                   (ot0-make-c25519-keypair)))
             (out-file FILE))
        (with-output-to-secret-file
         out-file
         (lambda () (write-subu8vector u8 0 (u8vector-length u8))))))))
  (define (make-vertex** more key-help? cont fail)
    ((match-lambda/doc+
      help fail "vertex properties did not parse" "vertex make"
      (("type:" (and (or "origin" "junction") TYPE) more ...) "vertex TYPE"
       (cont `(type: ,(string->symbol TYPE)) more))
      (((or "id:" "nonce:") NONCE more ...) "the vertex number"
       (cont `(nonce: ,(call-with-input-string NONCE read)) more))
      (("pk:" FILE more ...) "public key for update (default pk of signature)"
       (cont `(update-pk: ,(read-file-as-u8vector-or-fail "pk:" FILE)) more))
      (((or "sign:" "kp:") FILE more ...) "key pair for signature from FILE"
       (cont `(kp: ,(read-file-as-u8vector-or-fail "kp:" FILE)) more))
      (("edge:" IDENTIFIER ADDRESS.PORT..PERIOD ...)
       "add edge to unit IDENTIFIER followed by a list of ADDRESS and PORT until PERIOD
\tRepeated to add mutiple edges."
       (cont-with-list-to-end-marker-and-rest
        ADDRESS.PORT..PERIOD
        (lambda (addresses more)
          (let loop ((rest addresses)
                     (addresses '()))
            (match
             rest
             (() (cont (cons* edge: IDENTIFIER (reverse addresses)) more))
             ((addr port . rest)
              (loop rest
                    ;; Note: hides dependency on OT0-Syntax
                    (cons (string-append addr "/" port) addresses)))
             (_ (fail "address parsing failed" "make-vertex" addresses)))))))
      (((? end-marker? PERIOD) more ...) "" (cont 'done more))
      (() "" (cont 'done '())))
     more))
  (define (make-vertex* more key-help? cont fail)
    (define nonce #f)
    (define type 'origin)
    (define update-pk #f)
    (define kp #f)
    (define replicates '())
    (let loop ((res #f) (more more))
      (match
       res
       (('nonce: x) (begin (set! nonce x) (make-vertex** more key-help? loop fail)))
       (('type: x) (begin (set! type x) (make-vertex** more key-help? loop fail)))
       (('update-pk: x) (begin (set! update-pk x) (make-vertex** more key-help? loop fail)))
       (('kp: x) (begin (set! kp x) (make-vertex** more key-help? loop fail)))
       (('edge: . x) (begin (set! replicates (append replicates (list x)))
                            (make-vertex** more key-help? loop fail)))
       ('done (cont
               (ot0-make-vertex type: type nonce: nonce update-pk: (or update-pk kp) kp: kp replicates: replicates)
               more))
       (#f (make-vertex** more key-help? loop fail))
       (_ (error "vertex arguments did not parse" more more)))))
  (define (write-vertex-to-file-and-continue file result cont more)
    (when (ot0-vertex? result)
          (let ((done (make-pin)))
            (kick/sync (wire! done file done))
            (kick/sync (done (ot0-vertex->u8vector result)))
            (ot0-display-vertex result)))
    (cont more))
  (define vertex!
    (match-lambda/doc+
     help error-with-unhandled-params (cmd-line-parse-error) '("data tool" "vertex")
     (("make" FILE KP SRC (? PERIOD?) more ...) "create vertex in FILE from file SRC signed with KP"
      (write-vertex-to-file-and-continue
       FILE
       (if (file-exists? SRC)
           (eval `(ot0-make-vertex
                   kp: ',(or (read-file-as-u8vector KP)
                             (error "no key material"))
                   ,@(map (lambda (x) (list 'quote x)) (call-with-input-file SRC read-all))))
           (error "vertex source SRC does not exist file:" SRC))
       ot0command-line! more))
     (("make" FILE VERTEX_OPTIONS..PERIOD ...) "create vertex in FILE from VERTEX_OPTIONS..PERIOD"
      (make-vertex*
       VERTEX_OPTIONS..PERIOD key-help?
       (lambda (result rest)
         (write-vertex-to-file-and-continue FILE result ot0command-line! rest))
       error-with-unhandled-params))
     (("print" FILE more ...) "print vertex file"
      (let* ((file (read-file-as-u8vector-or-fail "vertex file" FILE))
             (vertex (u8vector->ot0-vertex file)))
        (unless vertex (error "file does not parse as vertex" FILE))
        (ot0-display-vertex vertex)
        (ot0command-line! more)))))
  (define identifier!
    (match-lambda/doc+
     help error-with-unhandled-params  (cmd-line-parse-error) '("data tool" "id")
     (("print" FILE more ...)
      (let* ((file (and (file-exists? FILE)
                        (call-with-input-file FILE
                          ;; read all from FILE into string (gambit specific)
                          (lambda (port) (read-line port #f)))))
             (result (and file (string->ot0-id file))))
        (unless result (error "file does not parse as identifier" FILE))
        (println (ot0-id->string result))
        (ot0command-line! more)))))
  (define colon-regex (rx ":"))
  (define ot0network!
    (match-lambda/doc+
     help error-with-unhandled-params (more "" (ot0command-line! more)) #f
     (("adhoc" START END ...)
      "calculate ad hoc network-id from port range START to optional END
\tHint: prefix with '#x' to read as hexadecimal, continues with more..."
      (let* ((start (call-with-input-string START read))
             (end-given
              (match END
                     ((port . more)
                      (let ((v (call-with-input-string port read)))
                        (and (number? v) v)))
                     (_ #f)))
             (end (or end-given start))
             (nwid (ot0-adhoc-network-id start end)))
        (println "decimal: " nwid " hex: '#x" (hexstr nwid 16) "'")
        (ot0network! (if end-given (cdr END) END))))
     (("mac" NETWORK UNIT more ...) "calculate \"MAC\" address from NETWORK and UNIT"
      (let* ((nwid (call-with-input-string NETWORK read))
             (ndid (call-with-input-string UNIT read))
             (result (ot0-network+node->mac nwid ndid)))
        (println (lwip-mac-integer->string (ot0-mac->network result)))
        (ot0network! more)))
     (("unit" NETWORK MAC more ...) "calculate unit address from NETWORK and MAC"
      (let* ((nwid (call-with-input-string NETWORK read))
             (mac (if (rx~ colon-regex MAC)
                      (string->number (rx//all colon-regex MAC) 16)
                      (call-with-input-string MAC read)))
             (result (ot0-network-mac->node nwid mac)))
        (println "decimal: " result " hex: '#x" (hexstr result 10) "'")
        (ot0network! more)))
     (("6plane" NETWORK UNIT PORT more ...) "calculate '6plane' address"
      (let* ((args (map (lambda (x) (call-with-input-string x read))
                        (list NETWORK UNIT PORT)))
             (result (apply make-6plane-addr args)))
        (println (socket-address->string result))
        (ot0network! more)))))
  (define ot0data!
    (match-lambda/doc+
     help error-with-unhandled-params (cmd-line-parse-error) '("data tool")
     (("vertex" more ...) "vertex commands" (vertex! more))
     (("id" more ...) "identifier commands" (identifier! more))
     (("net" more ...) "network calculator" (ot0network! more))))
  (define (help-full help . args) ;; TODO
    (println "NYI (Not Yet Implemented): extended help" (if (pair? args) (list " on '" args "'.") '()))
    (apply help args))
  (define ot0command-line!
    (match-lambda/doc+
     help error-with-unhandled-params (cmd-line-parse-error) "<*ROOT*>"
     (("-1-i" FILE) "create key material in FILE and exit (shorthand for \"-c25519 make-kp FILE -exit\")"
      (c25519! `("make-kp" ,(refuse-help-key-as-file-name FILE))))
     (("-1-i" FILE . args) "" ;; not documented catches other help/error use cases
      ;; TBD: move this case downwards to avoid useless matching
      (begin (when (pair? args) (display "Warning: ignoring additional arguments: ") (pp args))
             (c25519! `("make-kp" ,(refuse-help-key-as-file-name FILE)))))
     (("-A" DIR more ...) "Initialize context directory DIR."
      (if (ot0-context) (error "-A: once only and from the command line!")
          (begin
            (ot0-init-context! DIR)
            (ot0cli-admin! more key-help? ot0command-line! error-with-unhandled-params)
            (exit 0))))
     (("-B" DIR more ...) "Continue using (r/w) context directory DIR.
\t\tOptionally: DIR prefixed by (\"kind:\" NUMBER)"
      (using-context! DIR ot0command-line! more))
     (("-C" PORT more ...)
      "Connect to loopback PORT and send more... commands to the server and display resulting output"
      (let* ((port (call-with-input-string PORT read))
             (conn (and port (open-tcp-client port))))
        (unless (port? conn) (error "conn failed"))
        (write more conn)
        (force-output conn)
        (port-copy-through conn (current-output-port))
        (exit 0)))
     (("-D" more ...) "Daemonize (reserved, NYI)" (NYI "damonize"))
     (("-E" more ...) "Ephemeral instance (reserved, NYI)"
      (match
       more
       (((? key-help?) . more) (NYI "help on ephemeral instance"))
       (((or "in:" "using:" "dir:" "directory:") DIR . more)
        (if (ot0-context) (error "-E: once only and from the command line!")
            (begin
              (ot0-init-context! (refuse-help-key-as-file-name DIR))
              (ot0cli-admin! more key-help? ot0command-line! error-with-unhandled-params)
              (finally))))
       (() (NYI "ephemeral instance"))))
     (((or "-A" "-B" "-C")) "" (error "option requires an directory argument"))
     (("-status" more ...) "print status info" (print-status ot0command-line! more))
     (((or "-S" "-service") more ...) "service tool"
      (ot0cli-services! more key-help? ot0command-line! error-with-unhandled-params))
     (("-c25519" more ...) "c25519 tool" (c25519! more))
     (("-data" more ...) "data tool" (ot0data! more))
     (("-adm" more ...) "data directory administration commands"
      (ot0cli-admin! more key-help? ot0command-line! error-with-unhandled-params))
     (((or "-s" "-send") more ...) "send more... commands to ot0 units (continue after PERIOD)"
      (%ot0cli-client-commands! more key-help? ot0command-line! error-with-unhandled-params))
     (((or "-l" "-script") SCRIPT more ...) "load SCRIPT file and continue with more..."
      (begin (load SCRIPT) (ot0command-line! more)))
     (("-scripts" SCRIPT..PERIOD ...) "load SCRIPT..PERIOD files"
      (let ((then (lambda (scripts more) (for-each load scripts) (ot0command-line! more))))
        (cont-with-list-to-end-marker-and-rest SCRIPT..PERIOD then)))
     (("-tests" SCRIPT..PERIOD ...) "load remaining SCRIPT..PERIOD files and report test results"
      (let ((then (lambda (files more) (for-each load files) (tests-end) (ot0command-line! more))))
        (cont-with-list-to-end-marker-and-rest SCRIPT..PERIOD then)))
     (("-repl" (? key-help?) . more) "" ;; "magic": help key ot printed
      (begin
        (display "helpless here? try: ,? for help on commands ")
        (display " or ")
        (display "at least one character plus the TAB key for completion\n")
        ;; take the help key out and retry
        (ot0command-line! (cons "-repl" more))))
     (("-repl" more ...) "enter repl (interactive command loop)"
      (begin
        (display "ignoring command line rest (TBD: better figure out how to continue):\n\t")
        (display more) (display "\n\tremember ,? or see \"-repl -h\"\n")
        (replloop)
        (ot0command-line! more)))
     (("-wait") "wait for running services to exit" (%wait-for-services))
     (("-exit") "" (exit 0))
     (("-exit" CODE more ...) "exit now with optional CODE (default 0) more... is not evaluated, no final activity"
      (exit (or (string->number CODE) 0)))
     (("-p" PERIOD more ...)
      "set list closing delimitter to PERIOD (a regex by default \",:.;\")
\t\t- once only - before first match - mnemonic: 'period./pop/reduce'"
      (begin (set-end-marker! PERIOD) (ot0command-line! more)))
     (("-k" STYLE more ...) "set $kick-style to STYLE{async,sync,none} and continue
\tHint: use sync as first measure during debugging"
      (let ((style (match STYLE ((or "s" "sync") 'sync) ((or "a" "async") 'async) ((or "n" "none") #f))))
        ($kick-style style) (ot0command-line! more)))
     (("-kick" more ...) "continue within a transaction until \"-back\""
      (let ((rest (begin (ot0command-line! more))))
        (ot0command-line! (if (pair? rest) rest '()))))
     (("-back" more ...) "end the transaction since last \"-kick\" and continue with more..." more)
     (("-d" more ...) "set debug option and continue"
      (set-debug! more key-help? ot0command-line! error-with-unhandled-params))
     (() "continue with final activity (none by default)" (finally))
     (((or "-h" "-help" "--help") KEY ...) "help on KEY default \"top-level\""
      (match
       KEY
       (() (help)) ;; "top-level" (ensure this matched documented default above!)
       (("top-level" more ...) (help))
       (("all" more ...) (help-full help 'all))
       ((key more ...) (NYI "FIXME: KEY selection: " key) #;(help-full help))
       (else (for-each (lambda (k) (help-full help k)) KEY))))))
  (ot0command-line! args))

(define *ot0cli-tests*
  `(;;("-h")
    ;;
    ))

(define ot0cli-tests
  (case-lambda
   (() *ot0cli-tests*)
   ((x) (set! *ot0cli-tests* x))))

;; (ot0cli-tests (append (ot0cli-tests) '(("-S" "tcp" "register" "9051" socks-sever))))

(define (ot0srv! #!optional dir)
  (define cmd '("-S" "udp" "register" "9994" "ot0"))
  (if dir
      (ot0cli-1 `("-B" ,dir ,@cmd))
      (ot0cli-1 `("-B" ,dir ,@cmd))))

(ot0cli-1 (cdr (command-line)) (match (command-line) ((_) replloop) (_ (lambda () #t))))
