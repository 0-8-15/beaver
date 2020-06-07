(define-macro (delay-until-after-return expr) `(lambda () ,expr))

(define-macro (after-safe-return expr)
  ;; Schedule EXPR for execution (one way or another) and return nonsense.
  `(if (##in-safe-callback?)
       (delay-until-after-return ,expr)
       (begin (debug 'after-safe-return:not-in-callback ',expr) ,expr)))

(define-macro (in-safe-context expr)
  `(if (##in-safe-callback?)
       (begin (debug 'in-safe-context:NOT-SAFE! ',expr) (delay-until-after-return ,expr) #!void)
       (begin ,expr )))

(define-macro (after-safe-return+post r0 expr)
  ;; Schedule EXPR for execution (one way or another) and return nonsense.
  `(if (##in-safe-callback?) (begin (##safe-lambda-post! (delay-until-after-return ,expr)) ,r0)
       (begin (debug 'after-safe-return+post:not-in-callback ',expr) ,expr)))

(define-macro (mustbe-async expr)
  `(if (or (eq? ($kick-style) 'sync)
           (not (stm-atomic?)))
       (thread-start! (make-thread (lambda () ,expr #;(debug ',expr ,expr)) ',expr))
       (begin (debug 'mustbe-async:not-async ',expr) ,expr)))

(define-macro (lwip/after-safe-return expr)
  `(after-safe-return ,expr))

(define-macro (ot0/after-safe-return r0 expr)
  `(after-safe-return+post ,r0 ,expr))

(define-macro (mustbe-async-to-avoid-recursion-to-lwip expr) `(mustbe-async ,expr))

;;* EVENTS

(define ot0cli-on-ot0-received
  (box
   (lambda (type from reference data)
     (debug 'RECV-from (list type from reference (u8vector-length data)))
     #f)))

(on-ot0-recv
 (lambda (type from reference data)
   ;; required to hide `ot0/after-safe-return` macro here.
   (let ((receiver (unbox ot0cli-on-ot0-received)))
     (and receiver (ot0/after-safe-return #t (receiver type from reference data))))))

(define (ot0cli-ot0-event/debug node userptr thr event payload)
  (case event
    ((UP) ;; UP comes BEFORE the initialization is completed! Don't use it.
     (debug 'OT0-EVENT event) )
    ((ONLINE OFFLINE)
     (debug 'OT0-EVENT event)
     (ot0/after-safe-return
      #f
      (kick!
       (lambda ()
         #;(should-use-external #f)
         (ot0-online event)))))
    ((TRACE)
     (debug 'OT0-TRACE ((c-lambda ((pointer void)) char-string "___return(___arg1);") payload))
     (debug 'OT0-CFG (ot0-query-network-config-base->vector (ctnw))))
    (else (debug 'OT0-EVENT event))))

(define (ot0cli-ot0-event/default node userptr thr event payload)
  (case event
    ((UP) #f) ;; UP comes BEFORE the initialization is completed! Don't use it.
    ((ONLINE OFFLINE)
     (ot0/after-safe-return
      #f
      (kick!
       (lambda ()
         #;(should-use-external #f)
         (ot0-online event)))))
    ((TRACE)
     (debug 'OT0-TRACE ((c-lambda ((pointer void)) char-string "___return(___arg1);") payload))
     (debug 'OT0-CFG (ot0-query-network-config-base->vector (ctnw))))
    (else (debug 'OT0-EVENT event))))

(on-ot0-event ot0cli-ot0-event/default)

#;(on-ot0-wire-packet-send
 (lambda (udp socket remaddr data ttl)
   ;;(debug 'wire-send-via socket)
   (cond
    ((internet-socket-address? remaddr)
     (receive
      (ip-addr port) (socket-address->internet-address remaddr)
      (udp-destination-set! ip-addr port udp)
      (udp-write-u8vector data udp)
      #t))
    ((and #f (internet6-socket-address? remaddr)) ;; FIXME: Why does udp-destination-set! fail here?
     (receive
      (host port flowinfo scope-id) (socket-address->internet6-address remaddr)
      (udp-destination-set! host port udp))
     (udp-write-u8vector data udp)
     #t)
    (else #f))))

(define-values
  (ot0cli-wire-address-enabled?
   ot0cli-wire-address-add-filter!
   ot0cli-wire-address-remove-filter!)
  (let ((filters '()))
    (values
     (lambda (addr)
       (let loop ((filters filters))
         (or (null? filters)
             (and ((car filters) addr) (loop (cdr filters))))))
     (lambda (proc)
       (and (not (memq proc filters)) (set! filters (cons proc filters))))
     (lambda (proc)
       (set! filters (remove (lambda (x) (eq? x proc)) filters))))))

(define-values
  (%%ot0cli-wire-statistics-sent ot0cli-wire-statistics-print!)
  (let ((stats (vector 0 0))) ;; totals for calls and size
    (values
     ;; %%ot0cli-wire-statistics-sent
     (lambda (via addr port data)
       ;; It MUST be KNOWN that this is ever only called in syncrhon context!
       (vector-set! stats 0 (+ (vector-ref stats 0) 1))
       (vector-set! stats 1 (+ (vector-ref stats 1) (u8vector-length data))))
     ;; ot0cli-wire-statistics-print!
     (lambda ()
       (println "Total #packages: " (vector-ref stats 0)
                " transferred bytes: " (vector-ref stats 1))))))

(define-macro (%ot0-statistics:update-wire-send! via addr port data)
  `(%%ot0cli-wire-statistics-sent via addr port data))

(define (%ot0cli-ot-wire-packet-send via addr port data)
  (%ot0-statistics:update-wire-send! via addr port data)
  ;; TODO: maybe this could be done right now!?
  (ot0/after-safe-return
   0
   (begin #;maybe-async
     (udp-destination-set! addr port via)
     (udp-write-subu8vector data 0 (u8vector-length data) via)
     0)))

(define (ot0cli-ot0-wire-packet-send/debug via socket remaddr data len ttl)
  (thread-yield!) ;; KILLER!
  ;; (debug 'wire-send-via socket)
  ;; FIXME: allocate IPv6 too!
  (cond
   ((internet-socket-address? remaddr)
    (let ((addr (socket-address4-ip4addr remaddr))
          (port (socket-address4-port remaddr)))
      (thread-yield!) ;; KILLER!
      (##gc) ;; REALLY??
      (cond
       ((ot0cli-wire-address-enabled? addr)
        (debug 'wire-send-via (socket-address->string remaddr))
        (let ((u8 (make-u8vector len)))
          (unless (eqv? (lwip-gambit-locked?) 1) (error "locking issue"))
          ;; This COULD happen to copy from another threads stack!
          (u8vector-copy-from-ptr! u8 0 data 0 len)
          (thread-yield!) ;; KILLER!
          #;(debug 'remaddr-is-still-ipv4? (internet-socket-address? remaddr))
          #;(debug 'wire-send-via (socket-address->string remaddr))
          #;(eqv? (send-message via u8 0 #f 0 remaddr) len)
          (debug 'wire-sent (%ot0cli-ot-wire-packet-send via addr port u8))))
       (else (debug 'wire-send-via/blocked (socket-address->string remaddr)) 1))))
   ((internet6-socket-address? remaddr)
    (let ((addr (socket-address6-ip6addr remaddr))
          (port (socket-address6-port remaddr)))
      (cond
       ((ot0cli-wire-address-enabled? addr)
        (let ((u8 (make-u8vector len)))
          (u8vector-copy-from-ptr! u8 0 data 0 len)
          (debug 'wire-sent (%ot0cli-ot-wire-packet-send via addr port u8))))
       (else (debug 'wire-send-via/blocked (socket-address->string remaddr)) 1))))
   (else (error "ot0cli-ot0-wire-packet-send/debug : illegal address" remaddr) 1)))

(define (ot0cli-ot0-wire-packet-send/default via socket remaddr data len ttl)
  (cond
   ((internet-socket-address? remaddr)
    (let ((addr (socket-address4-ip4addr remaddr))
          (port (socket-address4-port remaddr)))
      (cond
       ((ot0cli-wire-address-enabled? addr)
        (let ((u8 (make-u8vector len)))
          (u8vector-copy-from-ptr! u8 0 data 0 len)
          (%ot0cli-ot-wire-packet-send via addr port u8)))
       (else (debug 'wire-send-via/blocked (socket-address->string remaddr)) 1))))
   ((internet6-socket-address? remaddr)
    (let ((addr (socket-address6-ip6addr remaddr))
          (port (socket-address6-port remaddr)))
      (cond
       ((ot0cli-wire-address-enabled? addr)
        (let ((u8 (make-u8vector len)))
          (u8vector-copy-from-ptr! u8 0 data 0 len)
          (%ot0cli-ot-wire-packet-send via addr port u8)))
       (else (debug 'wire-send-via/blocked (socket-address->string remaddr)) 1))))
   (else (error "ot0cli-ot0-wire-packet-send/default : illegal address" remaddr) 1)))

(on-ot0-wire-packet-send ot0cli-ot0-wire-packet-send/default)

(define (ot0cli-ot0-wire-trace-toggle!)
  (on-ot0-wire-packet-send
   (if (eq? (on-ot0-wire-packet-send) ot0cli-ot0-wire-packet-send/default)
       ot0cli-ot0-wire-packet-send/debug
       ot0cli-ot0-wire-packet-send/default)))

(define (make-ot0-ad-hoc-network-interface nwid ndid port)
  (let ((nif (lwip-make-netif (lwip-mac:host->network (ot0-network+node->mac nwid ndid)))))
    (if (netif? nif)
        (begin
          (ot0cli-add-nif! nwid nif) ;; required before initialization
          (lwip_init_interface_IPv6 nif (make-6plane-addr nwid ndid))
          ;; this goes south under valgrind (only) and valgrind will report mem leaks
          #;(do ((n (- (debug 'NMacs (lwip-netif-ip6addr-count nif)) 1) (- n 1)))
          ((= n -1))
          (ot0-multicast-subscribe nwid (lwip-netif-ip6broadcast-mach nif n)))))
    nif))

;;;* lwIP

(define-values
  (ot0cli-find-nif/mac
   ot0cli-find-nw/nif
   ot0cli-add-nif!
   ot0cli-remove-nif!
   ot0cli-nifs
   ot0cli-display-nifs)
  (let ((by-mac '())
        (by-nw '()))
    (values
     (lambda (mac) ;; ot0cli-find-nif/mac
       (let ((x (assoc mac by-mac)))
         (match x ((_ nif . more) nif) (_ #f))))
     (lambda (nif) ;; ot0cli-find-nw/nif
       (match
        (assoc (lwip-netif-mac nif) by-mac)
        ((mac nif nwid) nwid)
        (_ #f)))
     (lambda (nwid nif) ;; ot0cli-add-nif!
       (unless (netif? nif) (error "not a valid network interface" nif))
       (let* ((mac (lwip-netif-mac nif))
              (x (assoc mac by-mac)))
         (if x (error "MAC already known" mac)
             (set! by-mac (cons (list mac nif nwid) by-mac)))
         (if nwid
             (set! by-nw (cons (list nwid nif) by-nw)))))
     (lambda (nif) ;; ot0cli-remove-nif!
       (error "ot0cli-remove-nif! NYI"))
     (lambda () ;; ot0cli-nifs
       (map cdr by-mac))
     (lambda () ;;ot0cli-display-nifs
       (println
        "lwIP interfaces: "
        (map
         (match-lambda ((mac nif nwid) (list nwid " " (lwip-mac-integer->string mac))))
         by-mac))))))

(define (ot0cli-register-ot0adhoc-address #!key (network-id #f) (unit-id #f) (port 0))
  (unless network-id (error "illegal network id" network-id))
  (unless unit-id (error "illegal unit id" unit-id))
  (unless (and (fixnum? port) #;(positiv? port)) (error "illegal port id" port))
  (make-ot0-ad-hoc-network-interface network-id unit-id port))

(define (assemble-ethernet-pbuf src dst ethertype payload len)
  (let ((pbuf (or (make-pbuf-raw+ram (+ SIZEOF_ETH_HDR len))
                  (error "pbuf allocation failed"))))
    (pbuf-fill-ethernet-header! pbuf (lwip-mac:host->network src) (lwip-mac:host->network dst) ethertype)
    (pbuf-copy-from-ptr! pbuf payload SIZEOF_ETH_HDR len)
    pbuf))

(define (ot0cli-ot0-virtual-receive/debug node userptr thr nwid netptr srcmac dstmac ethertype vlanid payload len)
  (if (eq? ethertype ETHTYPE_IPV6)
      (let ((u8p (make-u8vector len)))
        (u8vector-copy-from-ptr! u8p 0 payload 0 len)
        (display-ip6-packet/offset u8p 0 (current-error-port))))
  (let ((nif (ot0cli-find-nif/mac dstmac)))
    (if nif
        (let ((pbuf (assemble-ethernet-pbuf srcmac dstmac ethertype payload len)))
          (ot0/after-safe-return #!void (lwip-send-ethernet-input! nif pbuf)))
        (begin
          (debug 'DROP:VRECV-DSTMAC (lwip-mac-integer->string (ot0-mac->network dstmac)))))))

(define (ot0cli-ot0-virtual-receive/default node userptr thr nwid netptr srcmac dstmac ethertype vlanid payload len)
  ;; API issue: looks like zerotier may just have disassembled a memory
  ;; segment which we now must copy bytewise.  If that's the case we
  ;; better had an interface to pass the underlying pointer.  NOTE:
  ;; It's (currently) important that LWIP_TCPIP_CORE_LOCKING_INPUT is
  ;; not set.
  (let ((nif (ot0cli-find-nif/mac dstmac)))
    (if nif
        (let ((pbuf (assemble-ethernet-pbuf srcmac dstmac ethertype payload len)))
          (ot0/after-safe-return #!void (lwip-send-ethernet-input! nif pbuf)))
        (begin
          (debug 'DROP:VRECV-DSTMAC (lwip-mac-integer->string (ot0-mac->network dstmac)))))))

(on-ot0-virtual-receive ot0cli-ot0-virtual-receive/default)

(lwip-nd6-get-gateway (lambda (netif dst) dst)) ;; ZT serves a single switch

(define (ot0cli-lwip-ethernet-send/debug netif src dst ethertype #;0 pbuf)
  (thread-yield!) ;; KILLER? - No, Yes.
  (let ((src (lwip-mac:network->host src))
        (dst (lwip-mac:network->host dst))
        (ethertype ethertype))
    #;(display-eth-packet/offset pbuf 0 (current-error-port))
    (let ((vlanid 0)
          (bp (pbuf->u8vector pbuf SIZEOF_ETH_HDR))) ;; FIXME: avoid the copy
      (cond
       ((eq? ethertype ETHTYPE_IPV6) (display-ip6-packet/offset bp 0 (current-error-port))))
      (lwip/after-safe-return (ot0-virtual-send (ot0cli-find-nw/nif netif) src dst ethertype vlanid bp)))))

(define (ot0cli-lwip-ethernet-send/default netif src dst ethertype #;0 pbuf)
  (let ((src (lwip-mac:network->host src))
        (dst (lwip-mac:network->host dst))
        (ethertype ethertype))
    #;(display-eth-packet/offset pbuf 0 (current-error-port))
    (let ((vlanid 0)
          (bp (pbuf->u8vector pbuf SIZEOF_ETH_HDR))) ;; FIXME: avoid the copy
      (lwip/after-safe-return (ot0-virtual-send (ot0cli-find-nw/nif netif) src dst ethertype vlanid bp))
      )))

(lwip-ethernet-send ot0cli-lwip-ethernet-send/default)

(define (lwip-ip6-send/debug netif pbuf ip6addr)
  (let ((addr (make-u8vector 16)))
    (u8vector-copy-from-ptr! addr 0 ip6addr 0 16) ;; GREAT, looks really simple and obvious!
    (if #t ;; (eqv? (u8vector-ref addr 0) #xfc)
        (let ((nwid (ot0cli-find-nw/nif netif)))
          (if nwid
              (let ((ndid (quotient (%u8vector/n48h-ref addr 5) 256)) ;; TBD where did I learn this?
                    (src (lwip-netif-mac netif))
                    (bp (pbuf->u8vector pbuf 0)))
                (display-ip6-packet/offset bp 0 (current-error-port))
                (lwip/after-safe-return (ot0-virtual-send nwid src (ot0-network+node->mac nwid ndid) ETHTYPE_IPV6 0 bp)))
              ERR_RTE))
        ERR_RTE)))

(define (lwip-ip6-send/default netif pbuf ip6addr)
  (let ((addr (make-u8vector 16)))
    (u8vector-copy-from-ptr! addr 0 ip6addr 0 16) ;; GREAT, looks really simple and obvious!
    (if #t ;; (eqv? (u8vector-ref addr 0) #xfc)
        (let ((nwid (ot0cli-find-nw/nif netif)))
          (if nwid
              (let ((ndid (quotient (%u8vector/n48h-ref addr 5) 256)) ;; TBD where did I learn this?
                    (src (lwip-netif-mac netif))
                    (bp (pbuf->u8vector pbuf 0)))
                (lwip/after-safe-return (ot0-virtual-send nwid src (ot0-network+node->mac nwid ndid) ETHTYPE_IPV6 0 bp)))
              ERR_RTE))
        ERR_RTE)))

(lwip-ip6-send lwip-ip6-send/default)

(define (ot0cli-ot0-trace-toggle!)
  (cond
   ((eq? (on-ot0-virtual-receive) ot0cli-ot0-virtual-receive/default)
    (on-ot0-event ot0cli-ot0-event/debug)
    (on-ot0-virtual-receive ot0cli-ot0-virtual-receive/debug)
    (lwip-ethernet-send ot0cli-lwip-ethernet-send/debug)
    (lwip-ip6-send lwip-ip6-send/debug)
    (on-ot0-virtual-config ot0cli-on-ot0-virtual-config/debug)
    (on-ot0-path-check ot0cli-on-ot0-path-check/debug))
   (else
    (on-ot0-event ot0cli-ot0-event/default)
    (on-ot0-virtual-receive ot0cli-ot0-virtual-receive/default)
    (lwip-ethernet-send ot0cli-lwip-ethernet-send/default)
    (lwip-ip6-send lwip-ip6-send/default)
    (on-ot0-virtual-config ot0cli-on-ot0-virtual-config/default)
    (on-ot0-path-check ot0cli-on-ot0-path-check/default))))

;; Config

(define config-helper
  (thread-start!
   (make-thread
    (lambda ()
      (let loop ()
        (thread-receive)
        (ot0-set-config-item! (ctnw) 2 16)
        (loop))))))

(define (ot0cli-on-ot0-virtual-config/debug node userptr nwid netptr op config)
  #;(thread-yield!) ;; KILLER? - No
  (debug 'CONFIG op)
  (debug 'CFG (ot0-virtual-config-base->vector config))
  ;; set multicast limit
  ;;(thread-send config-helper #t)
  ;;(if (eqv? nwid (ctnw)) (maybe-async-when-lwip-requires-pthread-locks (debug 'set-mc-limit (ot0-set-config-item! nwid 2 16))))
  0)

#;(define (ot0cli-on-ot0-virtual-config/default node userptr nwid netptr op config)
  0)

(define ot0cli-on-ot0-virtual-config/default #f)

(on-ot0-virtual-config ot0cli-on-ot0-virtual-config/default)

;; Optional

(define (ot0cli-on-ot0-path-check/debug node userptr thr nodeid socket sa)
  (debug 'PATHCHECK (number->string nodeid 16))
  ;; (debug 'PATHCHECK:gamit-locked? (lwip-gambit-locked?))
  (unless (eqv? (lwip-gambit-locked?) 1) (error "locking issue, ot0-path-check"))
  (if (socket-address? sa)
      (receive
       (addr port)
       (case (socket-address-family sa)
         ((2) (values (socket-address4-ip4addr sa) (socket-address4-port sa)))
         ((10) (values (socket-address6-ip6addr sa) (socket-address6-port sa)))
         (else (values #f #f)))
       (debug 'PATHCHECK (cons addr port))
       (ot0cli-wire-address-enabled? addr))))

(define (ot0cli-on-ot0-path-check/default node userptr thr nodeid socket sa)
  (if (socket-address? sa)
      (receive
       (addr port)
       (case (socket-address-family sa)
         ((2) (values (socket-address4-ip4addr sa) (socket-address4-port sa)))
         ((10) (values (socket-address6-ip6addr sa) (socket-address6-port sa)))
         (else (values #f #f)))
       (ot0cli-wire-address-enabled? addr))))

(on-ot0-path-check ot0cli-on-ot0-path-check/default)


;; FIXME, CRAZY: Just intercepting here causes havoc under valgrind!

(on-ot0-path-lookup
 (lambda (node uptr thr nodeid family sa)
   ;; (debug 'LOOKUP (number->string nodeid 16))
   (debug 'LOOKUP (hexstr nodeid 12))
   (debug 'LookupFamily family)
   #f))

(on-ot0-maintainance
 (lambda (prm thunk)
   #; (debug 'ot0-maintainance (lwip-gambit-locked?))
   thunk))
