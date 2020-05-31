#|

* Threat Model

- (ot0-send! to type data)  :: ;; EXPORT - send user message (u8vector)

  Cause: Any peer knowing /to/ as our MAC *MAY* possible *DoS/SPAM* us.
    (Would cause O(2) traffic increase: /to/ sending multiple packets our way
     we too. )

  Mitigation:
    - change frequently
    - avoid ad-hoc networks

  Defence:
    - use network management
      -> 1. NO P2P until JOIN succeeded.
      -> 2. (since: "change frequently" OR "may have leaked"):
         consider "take down" measurements.
      -> ...
|#

;;;* Compile Time Configuration

;; (define-cond-expand-feature ot0-locking)
(define-cond-expand-feature ot0-safe-locking)

(declare
 (standard-bindings)
 (extended-bindings) ;; no overwrites of standard bindings
 (not standard-bindings thread-start!) ;; except this
 (block)
 )

;;;* From Elsewhere

#;(define (u8vector-copy-from-ptr! u8 u8o ptr ptro len)
  ;; TBD: Add range checks
  ((c-lambda
    (scheme-object size_t void* size_t size_t) scheme-object
    "memcpy(___CAST(char *,___BODY(___arg1)) + ___arg2, ___CAST(char *,___arg3) + ___arg4, ___arg5);
    ___return(___arg1);")
   u8 u8o ptr ptro len))

(define-macro (%%uninitialized-procedure location setter)
  `(lambda _
     (error "PHASE ERROR: still unbound, setter MUST be called during initialization"
            ,location ,setter)))

(define *%socket-address->string*
  (%%uninitialized-procedure 'ot0core:socket-address->string 'ot0core-socket-address->string-set!))
(define-macro (%socket-address->string sa) `(*%socket-address->string* ,sa))
(define (ot0core-socket-address->string-set! proc) (set! *%socket-address->string* proc))

(define *%ot0-string->socket-address*
  (%%uninitialized-procedure 'ot0-string->socket-address 'ot0core-string->socket-address-set!))
(define-macro (%ot0-string->socket-address str) `(*%ot0-string->socket-address* ,str))
(define (ot0core-string->socket-address-set! proc) (set! *%ot0-string->socket-address* proc))

;;;* Macros
(define-macro (c-safe-lambda formals return c-code)
  (let ((tmp (gensym 'c-safe-lambda-result))
        (argument-names
         (map
          (lambda (n) (string->symbol (string-append "arg" (number->string n))))
          (iota (length formals)))))
    `(lambda ,argument-names
       (##safe-lambda-lock! ,c-code)
       (let ((,tmp ((c-lambda ,formals ,return ,c-code) . ,argument-names)))
         (##safe-lambda-unlock! ,c-code)
         ,tmp))))

(define-macro (delayed-until-after-return? expr) `(procedure? ,expr))
(define-macro (%ot0-post expr)
  (let ((result (gensym '%ot0-post)))
    `(let ((,result ,expr))
       (if (delayed-until-after-return? ,result)
           (begin
             (##safe-lambda-post! ,result) ZT_RESULT_OK)
           ,result))))

(define-macro (define-c-constant var type . const)
  (let* ((const (if (not (null? const)) (car const) (symbol->string var)))
	 (str (string-append "___return(" const ");")))
    `(define ,var ((c-lambda () ,type ,str)))))

;; There's an issue with gambit when using `set!` - it does sometimes,
;; but not always set what I expect.

(define-macro (define-custom name initial)
  `(define ,name
     (let ((val ,initial))
       (case-lambda
        (() val)
        ((x) (set! val x))))))
(c-declare #<<c-declare-end

#ifndef OT0_BOOL_DEFINED
#define OT0_BOOL_DEFINED 1
typedef enum {false=0, true=1} bool;
#endif
#include <zerotiercore/ZeroTierOne.h>
#include <stdlib.h>
#include <string.h>

// snprintf
#include <stdio.h>

c-declare-end
)

;; There should be only one ZT per process.  ZT is tricky enough.

(define-macro (assert-ot0-up! caller) `(or (ot0-up?) (error "ZT not running" ',caller)))

(c-declare #<<END
static uint64_t zt_now()
{
#ifdef __WINDOWS__
 FILETIME ft;
 SYSTEMTIME st;
 ULARGE_INTEGER tmp;
 GetSystemTime(&st);
 SystemTimeToFileTime(&st,&ft);
 tmp.LowPart = ft.dwLowDateTime;
 tmp.HighPart = ft.dwHighDateTime;
 return (int64_t)( ((tmp.QuadPart - 116444736000000000LL) / 10000L) + st.wMilliseconds );
#else
 #include <sys/time.h>
 struct timeval tv;
//#ifdef __LINUX__
// syscall(SYS_gettimeofday,&tv,0); /* fix for musl libc broken gettimeofday bug */
//#else
 gettimeofday(&tv,(struct timezone *)0);
//#endif
 return ( (1000LL * (int64_t)tv.tv_sec) + (int64_t)(tv.tv_usec / 1000) );
#endif
}
END
)

(define ot0-now (c-lambda () unsigned-int64 "zt_now"))

(define-c-constant ZT_RESULT_OK int "ZT_RESULT_OK")

;;(c-define-type void* (pointer "void"))

(c-define-type void** (pointer (pointer "void")))

(c-define-type ot0-node (pointer "ZT_Node"))

;; (c-define-type socket-address (pointer (struct "sockaddr_storage") socket-address))
;;
;; DON't repeat the type with the same tag in different
;; files. ot0-socket-address are read only, managed by ZT.
;; (c-define-type ot0-socket-address (pointer (struct "sockaddr_storage") ot0-socket-address))
(c-define-type ot0-socket-address (pointer (struct "sockaddr_storage") socket-address))
;; From gamsock owned we get another tag - those managed by gambit GC.
(c-define-type gamsock-socket-address (pointer (struct "sockaddr_storage") socket-address))

(define ot0->gamsock-socket-address
  (c-lambda (ot0-socket-address) gamsock-socket-address "___return(___arg1);"))

#;(define gamsock->ot0-socket-address
  (c-lambda (gamsock-socket-address) ot0-socket-address "___return(___arg1);"))

(c-define-type ot0-message (pointer "ZT_UserMessage" ot0-message))

(c-define-type ZT_NodeStatus (pointer "ZT_NodeStatus"))

(c-define-type ot0-virtual-config* (pointer "ZT_VirtualNetworkConfig" ot0-virtual-config))

(c-define-type ot0-peers (pointer "ZT_PeerList" ot0-peers))

(c-define-type ot0-peer (pointer "ZT_Peer" ot0-peer))

(c-define-type ZT_PeerPhysicalPath (pointer "ZT_PeerPhysicalPath" ZT_PeerPhysicalPath))

(define-macro (%%checked location expr fail)
  `(with-exception-catcher
    (lambda (ex)
      (debug ',location ex)
      (##default-display-exception ex (current-error-port))
      ,fail)
    (lambda () (%ot0-post ,expr))))

;; ZT event callback (ot0-event node userptr thr event payload)

(define-c-constant ZT_EVENT_UP int "ZT_EVENT_UP")
(define-c-constant ZT_EVENT_OFFLINE int "ZT_EVENT_OFFLINE")
(define-c-constant ZT_EVENT_ONLINE int "ZT_EVENT_ONLINE")
(define-c-constant ZT_EVENT_DOWN int "ZT_EVENT_DOWN")
(define-c-constant ZT_EVENT_FATAL_ERROR_IDENTITY_COLLISION int "ZT_EVENT_FATAL_ERROR_IDENTITY_COLLISION")
(define-c-constant ZT_EVENT_TRACE int "ZT_EVENT_TRACE")
(define-c-constant ZT_EVENT_USER_MESSAGE int "ZT_EVENT_USER_MESSAGE")
(define-c-constant ZT_EVENT_REMOTE_TRACE int "ZT_EVENT_REMOTE_TRACE")

(define-custom on-ot0-event #f) ;; EXPORT HOOK - network events

(c-define
 (ot0-event-cb node userptr thr event payload)
 (ot0-node void* void* int void*)
 void "scm_zt_event_cb" "static"
 (let ()
   (define (onevt e)
     (cond
      ((eqv? ZT_EVENT_UP e) 'UP)
      ((eqv? ZT_EVENT_OFFLINE e) 'OFFLINE)
      ((eqv? ZT_EVENT_ONLINE e) 'ONLINE)
      ((eqv? ZT_EVENT_DOWN e) 'DOWN)
      ((eqv? ZT_EVENT_FATAL_ERROR_IDENTITY_COLLISION e) 'FATAL_ERROR_IDENTITY_COLLISION)
      ((eqv? ZT_EVENT_TRACE e) 'TRACE)
      ((eqv? ZT_EVENT_REMOTE_TRACE e) 'REMOTE_TRACE)
      (else 'ZT_EVENT_UNKNOWN)))
   (cond
    ((procedure? (on-ot0-event)) (%%checked on-ot0-event ((on-ot0-event) node userptr thr (onevt event) payload) #f)))))

(define-custom on-ot0-recv #f) ;; EXPORT HOOK - user messages

(c-define
 (zt_recv node userptr thr payload)
 (ot0-node void* void* ot0-message)
 void "scm_zt_recv" "static"
 (cond
  ((procedure? (on-ot0-recv))
   (let ((size ((c-lambda (ot0-message) size_t "___return(___arg1->length);") payload))
         (from ((c-lambda (ot0-message) size_t "___return(___arg1->origin);") payload))
         (type ((c-lambda (ot0-message) size_t "___return(___arg1->typeId);") payload)))
     (let ((data (make-u8vector size)))
       ((c-lambda
         (scheme-object ot0-message) void
         "memcpy(___CAST(void *,___BODY_AS(___arg1,___tSUBTYPED)), ___arg2->data, ___arg2->length);")
        data payload)
       (%%checked on-ot0-recv ((on-ot0-recv) from type data) #t))))))

(c-declare #<<c-declare-end
static void
zt_event_cb(ZT_Node *node, void *userptr, void *thr, enum ZT_Event event, const void *payload)
{
 switch(event) {
  case ZT_EVENT_USER_MESSAGE: scm_zt_recv(node, userptr, thr, (ZT_UserMessage*)payload); break;
  default: scm_zt_event_cb(node, userptr, thr, event, (void *) payload);
 }
}
c-declare-end
)

;; ZT State

(define-c-constant ZT_STATE_OBJECT_NULL int "ZT_STATE_OBJECT_NULL")
(define-c-constant ZT_STATE_OBJECT_IDENTITY_PUBLIC int "ZT_STATE_OBJECT_IDENTITY_PUBLIC") ;; required
(define-c-constant ZT_STATE_OBJECT_IDENTITY_SECRET int "ZT_STATE_OBJECT_IDENTITY_SECRET") ;; required
(define-c-constant ZT_STATE_OBJECT_PLANET int "ZT_STATE_OBJECT_PLANET") ;; recommended
(define-c-constant ZT_STATE_OBJECT_MOON int "ZT_STATE_OBJECT_MOON") ;; required
(define-c-constant ZT_STATE_OBJECT_PEER int "ZT_STATE_OBJECT_PEER") ;; optional
(define-c-constant ZT_STATE_OBJECT_NETWORK_CONFIG int "ZT_STATE_OBJECT_NETWORK_CONFIG") ;; required

(define-custom on-ot0-state-get #f) ;; EXPORT HOOK - read state

(define (ot0-state-id->symbol e) ;; EXPORT
  (cond
   ((eqv? ZT_STATE_OBJECT_IDENTITY_PUBLIC e) 'IDENTITY_PUBLIC)
   ((eqv? ZT_STATE_OBJECT_IDENTITY_SECRET e) 'IDENTITY_SECRET)
   ((eqv? ZT_STATE_OBJECT_PLANET e) 'ORIGIN)
   ((eqv? ZT_STATE_OBJECT_MOON e) 'JUNCTION)
   ((eqv? ZT_STATE_OBJECT_PEER e) 'UNIT)
   ((eqv? ZT_STATE_OBJECT_NETWORK_CONFIG e) 'NETWORK_CONFIG)
   (else 'NULL)))

(c-define
 (zt_state_get node userptr thr objtype objid into len)
 (ot0-node void* void* int unsigned-int64 void* size_t)
 int "scm_zt_state_get" "static"
 (if (procedure? (on-ot0-state-get))
     (let ((v ((on-ot0-state-get) objtype objid)))
       (if (u8vector? v)
           (let ((n (min (u8vector-length v) len)))
             ((c-lambda
               (void* scheme-object size_t) void
               "memcpy(___arg1, ___CAST(void *,___BODY_AS(___arg2,___tSUBTYPED)), ___arg3);")
              into v n)
             n)
           -1))
     -1))

(define-custom on-ot0-state-put #f) ;; EXPORT HOOK - set state

(c-define
 (zt_state_put node userptr thr objtype objid from len)
 (ot0-node void* void* int unsigned-int64 void* size_t)
 void "scm_zt_state_put" "static"
 (if (procedure? (on-ot0-state-put))
     (let ((data (make-u8vector len)))
       ((c-lambda
         (scheme-object void* size_t) void
         "memcpy(___CAST(void *,___BODY_AS(___arg1,___tSUBTYPED)), ___arg2, ___arg3);")
        data from len)
       ((on-ot0-state-put) objtype objid data))))

(c-declare #<<c-declare-end

/*
 * This function should return the number of bytes actually stored to the
 * buffer or -1 if the state object was not found or the buffer was too
 * small to store it.
 */

static int
zt_state_get(ZT_Node *node, void *userptr, void *thr,
    enum ZT_StateObjectType objtype, const uint64_t objid[2], void *data,
    unsigned int len)
{
 //;; objid is a vector -- BUT WHY ??? !!!
 //if(objid) fprintf(stderr, "GET ID %lx - %lx\n", objid[0], objid[1]);
 //if(objid[1] != 0) fprintf(stderr, "GET ID %lx - %lx\n", objid[0], objid[1]);
 return scm_zt_state_get(node, userptr, thr, objtype, objid ? objid[0] : 0, data, len);
}

static void
zt_state_put(ZT_Node *node, void *userptr, void *thr,
    enum ZT_StateObjectType objtype, const uint64_t objid[2], const void *data,
    int len)
{
 //if(objid) fprintf(stderr, "PUT ID %lx - %lx\n", objid[0], objid[1]);
 //if(objid[1] != 0) fprintf(stderr, "PUT ID %lx - %lx\n", objid[0], objid[1]);
 scm_zt_state_put(node, userptr, thr, objtype, objid ? objid[0] : 0, (void*)data, len);
}

// ;; TZ nextBackgroundTaskDeadline
static volatile int64_t nextBackgroundTaskDeadline;

c-declare-end
)

(define ot0-bg-deadline (c-lambda () unsigned-int64 "___return(nextBackgroundTaskDeadline);"))

;;* ZT Network

;;** Sledgehammer LOCKing

(cond-expand
 (ot0-safe-locking
  ;; Needs to protect against: a) reentrance b) thread switch in
  ;; gambit which could cause other c(-safe)-lambda to be called
  ;; causing havoc.
  (define ot0-lock!
    (case-lambda
     (() (##safe-lambda-lock! 'ZT))
     ((location) (##safe-lambda-lock! location))))

  (define ot0-unlock!
    (case-lambda
     (() (##safe-lambda-unlock! 'ZT))
     ((location) (##safe-lambda-unlock! location))))

  (define (ot0-locking-set! lck ulk) (debug "zt compiled for c-safe-lambda" 'ignored))
  (define-macro (OT0-c-safe-lambda formals result code)
    `(c-safe-lambda ,formals ,result ,code))
  (define-macro (begin-ot0-exclusive expr) expr))
 (ot0-locking
  ;; exposes race condition
  (define ot0-features-locking #t)
  (define ot0-lock! #!void)

  (define ot0-unlock!
    (let ((mux (make-mutex 'zt)))
      (set! ot0-lock! (lambda () (debug 'ot0-lock-O (current-thread))
                             (debug 'ot0-lock-state: (mutex-state mux))
                             (if (eq? (mutex-state mux) (current-thread))
                                 (debug "\nDEAD " 'LOCK))
                             (mutex-lock! mux) (debug 'ot0-lock-P  (current-thread))))
      (lambda () (debug 'ot0-lock-V  (current-thread)) (mutex-unlock! mux))))

  #;(define ot0-unlock!
    (let ((mux (make-mutex 'zt)))
      (set! ot0-lock! (lambda () (mutex-lock! mux)))
      (lambda () (mutex-unlock! mux))))

  (define (ot0-locking-set! lck ulk) (set! ot0-lock! lck) (set! ot0-unlock! ulk))

  (define-macro (OT0-c-safe-lambda formals result code)
    `(c-lambda ,formals ,result ,code))

  (define-macro (begin-ot0-exclusive expr)
    (let ((result (gensym 'result)))
      `(let ((,result (begin (ot0-lock!) ,expr)))
         (ot0-unlock!)
         ,result))))
 (else
  (define ot0-features-locking #f)
  (define (ot0-locking-set! lck ulk) (debug "zt not compiled for ot0-locking" 'ignored))
  (define-macro (OT0-c-safe-lambda formals result code) `(c-lambda ,formals ,result ,code))
  (define-macro (begin-ot0-exclusive expr) expr)))

;;** ZT Network Wire
;;*** ZT Network Wire Incoming

;; Maybe we should not make this reachable outside this module.
;; Standard use is from the packet receiving thread.
(define (ot0-wire-packet-process packet from)
  (define doit
    (c-safe-lambda
     ;; 1     lsock addr              data          7
     (ot0-node int64 ot0-socket-address scheme-object size_t) bool #<<END
     int rc = -1;
     rc = ZT_Node_processWirePacket(___arg1, NULL, zt_now(), ___arg2, (void *) ___arg3,
             ___CAST(void *,___BODY_AS(___arg4,___tSUBTYPED)), ___arg5, &nextBackgroundTaskDeadline);
     ___return(rc == ZT_RESULT_OK);
END
))
  (when
   (ot0-up?)
   (or
    (begin-ot0-exclusive
     (doit (ot0-prm-ot0 %%ot0-prm) 0 from #;(gamsock->ot0-socket-address from) packet (u8vector-length packet)))
    (error "ot0-wire-packet-process: failed"))))

;;*** ZT Network Wire Outgoing

;; There is only so much reason to be able to overwrite this.  (Except
;; for debugging.)  Maybe we should at least have a decent default
;; here.

(define-custom on-ot0-wire-packet-send #f) ;; EXPORT?? HOOK - send via UDP
(define-custom on-ot0-wire-packet-send-complex #f) ;; EXPORT?? - send via UDP - MUST NOT raise exceptions

(c-define
 (zt_wire_packet_send node userptr thr socket remaddr data len ttl)
 (ot0-node scheme-object void* int ot0-socket-address void* size_t unsigned-int)
 int "scm_zt_wire_packet_send" "static"
 ;; BEWARE:
 (cond
  ((not (ot0-up?)) -1)
  ((procedure? (on-ot0-wire-packet-send-complex))
   (%ot0-post ((on-ot0-wire-packet-send-complex) node userptr thr socket remaddr data len ttl)))
  ((procedure? (on-ot0-wire-packet-send))
   (%%checked
    zt_wire_packet_send
    (let ((udp (ot0-prm-udp %%ot0-prm)))
      (or ((on-ot0-wire-packet-send) udp socket remaddr data len ttl) -1))
    -1))
  (else -1)))

(c-declare #<<c-declare-end

// This function is called when ZeroTier desires to send a
// physical frame. The data is a UDP payload, the rest of the
// payload should be set over vanilla UDP.
static int
zt_wire_packet_send(ZT_Node *node, void *userptr, void *thr, int64_t socket,
    const struct sockaddr_storage *remaddr, const void *data, unsigned int len,
    unsigned int ttl)
{
 return scm_zt_wire_packet_send(node, (___SCMOBJ) userptr, thr, socket, (struct sockaddr_storage*)remaddr, (void*)data, len, ttl);
}
c-declare-end
)

;;** ZT Network Virtual

;;*** ZT Network Virtual Incoming
(define-custom on-ot0-virtual-receive #f) ;; EXPORT HOOK

(c-define
 (zt_virtual_receive node userptr thr nwid netptr srcmac dstmac ethertype vlanid payload len)
 (ot0-node void* void* unsigned-int64 void** unsigned-int64 unsigned-int64 unsigned-int unsigned-int void* size_t)
 void "scm_zt_virtual_recv" "static"
 (if (procedure? (on-ot0-virtual-receive))
     (%%checked
      zt_virtual_receive
      ((on-ot0-virtual-receive) node userptr thr nwid netptr srcmac dstmac ethertype vlanid payload len)
      #f)))

(c-declare #<<c-declare-end

static void
zt_virtual_recv(ZT_Node *node, void *userptr, void *thr, uint64_t nwid,
    void **netptr, uint64_t srcmac, uint64_t dstmac, unsigned int ethertype,
    unsigned int vlanid, const void *payload, unsigned int len)
{
 scm_zt_virtual_recv(node, userptr, thr, nwid, netptr, srcmac, dstmac, ethertype, vlanid, (void*)payload, len);
}

c-declare-end
)

;;*** ZT Network Virtual outgoing

;;
(define (ot0-virtual-send nwid srcmac dstmac ethertype vlanid payload) ;; EXPORT
  (define virtual-send
    (c-safe-lambda
     ;; 1     2 nwid         3 src          4 dst          5 ethertype  6 vlan       7
     (ot0-node unsigned-int64 unsigned-int64 unsigned-int64 unsigned-int unsigned-int scheme-object size_t)
     bool #<<END
     ___return(ZT_Node_processVirtualNetworkFrame(___arg1, NULL, zt_now(),
                ___arg2, ___arg3, ___arg4, ___arg5, ___arg6,
                ___CAST(void *, ___BODY_AS(___arg7, ___tSUBTYPED)), ___arg8,
                &nextBackgroundTaskDeadline)
              == ZT_RESULT_OK);
END
))
  (assert-ot0-up! ot0-virtual-send)
  (begin-ot0-exclusive
   (virtual-send (ot0-prm-ot0 %%ot0-prm) nwid srcmac dstmac ethertype vlanid payload (u8vector-length payload))))

(define (ot0-virtual-send/ptr nwid srcmac dstmac ethertype vlanid data len) ;; EXPORT
  (define doit
    (c-safe-lambda
     ;; 1     2 nwid         3 src          4 dst          5 ethertype  6 vlan       7
     (ot0-node unsigned-int64 unsigned-int64 unsigned-int64 unsigned-int unsigned-int void* size_t)
     bool #<<END
     ___return(ZT_Node_processVirtualNetworkFrame(___arg1, NULL, zt_now(),
                 ___arg2, ___arg3, ___arg4, ___arg5, ___arg6,
                 ___arg7, ___arg8,
                 &nextBackgroundTaskDeadline)
              == ZT_RESULT_OK);
END
))
  (assert-ot0-up! ot0-virtual-send)
  (begin-ot0-exclusive (doit (ot0-prm-ot0 %%ot0-prm) nwid srcmac dstmac ethertype vlanid data len)))

;;* ZT Config

(define-custom on-ot0-virtual-config #f) ;; EXPORT

(c-define
 (zt_virtual_config0 node userptr thr nwid netptr op config)
 (ot0-node void* void* unsigned-int64 void** int ot0-virtual-config*)
 int "scm_zt_virtual_config" "static"
 (let ((opsym (let ((config-operations '#(#f up update down destroy)))
                (lambda (op) (vector-ref config-operations op)))))
   ;; TODO: Make sure multicastSubscribe() or other network-modifying
   ;; methods are disabled while handling is running as it may
   ;; deadlock.  Would it actually?
   (if (procedure? (on-ot0-virtual-config))
       (%%checked
        zt_virtual_config
        (or ((on-ot0-virtual-config) node userptr nwid netptr (opsym op) config) -1)
        0)
       0)))

(c-declare #<<c-declare-end
static int
zt_virtual_config(ZT_Node *node, void *userptr, void *thr, uint64_t nwid,
                  void **netptr, enum ZT_VirtualNetworkConfigOperation op,
                  const ZT_VirtualNetworkConfig *config)
{
 return scm_zt_virtual_config(node, userptr, thr, nwid, netptr, op, (ZT_VirtualNetworkConfig *)config);
}
c-declare-end
)

;; ZT Path

(define-custom on-ot0-path-check #f)

(c-define
 (zt_path_check node userptr thr nodeid socket sa)
 (ot0-node void* void* unsigned-int64 int ot0-socket-address)
 bool "scm_zt_path_check" "static"
 (if (procedure? (on-ot0-path-check))
     (%%checked
      zt_path_check
      ((on-ot0-path-check) node userptr thr nodeid socket sa)
      #f)
     ;; otherwise use it
     #t))

(define-custom on-ot0-path-lookup #f)

(c-define
 (zt_path_lookup node uptr thr nodeid family sa)
 (ot0-node void* void* unsigned-int64 int ot0-socket-address)
 bool "scm_zt_path_lookup" "static"
 (if (procedure? (on-ot0-path-lookup))
     (%%checked zt_path_lookup ((on-ot0-path-lookup) node uptr thr nodeid family sa) #f)
     ;; otherwise nothing returned
     #f))

(c-declare #<<c-declare-end
static int
zt_path_check(ZT_Node * node, void *uptr, void *tptr,
              uint64_t nodeid, int64_t socket, const struct sockaddr_storage * sa)
{
 return scm_zt_path_check(node, uptr, tptr, nodeid, socket, (struct sockaddr_storage *)sa);
}

static int
zt_path_lookup(ZT_Node *node, void *uptr, void * tptr, uint64_t nodeid, int family, struct sockaddr_storage * sa)
{
 return scm_zt_path_lookup(node, uptr, tptr, nodeid, family, sa);
}

static struct ZT_Node_Callbacks zt_callbacks = {
	.version                      = 0,
	.statePutFunction             = zt_state_put,
	.stateGetFunction             = zt_state_get,
	.wirePacketSendFunction       = zt_wire_packet_send,
	.virtualNetworkFrameFunction  = zt_virtual_recv,
	.virtualNetworkConfigFunction = zt_virtual_config,
	.eventCallback                = zt_event_cb,
	.pathCheckFunction            = zt_path_check,
	.pathLookupFunction           = zt_path_lookup
};

c-declare-end
)

(define ot0-background-period/lower-limit (make-parameter 0.60))

;; ot0-pre-maintainance is a hook/predicate.  Should be used to add to mainainace.
;; RETURN: #t to run or #f to suppress running the ZT background tasks.

(define-custom on-ot0-maintainance (lambda (prm thunk) thunk)) ;; EXPORT

(define-structure ot0-prm ot0 udp incoming-thread)
(define %%ot0-prm #f) ;; keep a scheme pointer to auxillary stuff
(define (ot0-node-init! udp receive-message #!key (now (ot0-now)) (background-period 5))
  (define (init ot0 now)
    ((c-safe-lambda
      (scheme-object (pointer void) int64) ot0-node #<<END
nextBackgroundTaskDeadline = ___arg3;
static ZT_Node *zt_node = NULL;
int rc=ZT_Node_new(&zt_node, (void*) ___arg1, ___arg2, &zt_callbacks, nextBackgroundTaskDeadline);
___return(rc == ZT_RESULT_OK ? zt_node : NULL);
END
)
     ot0 #f now))
  (define (exn-catcher ex) (debug (thread-name (current-thread)) ex)
    (##default-display-exception ex (current-error-port)))
  (define (recv-loop)
    (let ((prm %%ot0-prm))
      (when prm
            (with-exception-catcher
             exn-catcher
             (lambda ()
               (call-with-values receive-message ot0-wire-packet-process)))
            (recv-loop))))
  (define (maintainance)
    ((c-safe-lambda
      (ot0-node) bool #<<END
      uint64_t now = zt_now();
      int rc = nextBackgroundTaskDeadline <= now ?
      ZT_Node_processBackgroundTasks(___arg1, NULL, now, &nextBackgroundTaskDeadline) : ZT_RESULT_OK;
      ___return(rc == ZT_RESULT_OK);
END
) (ot0-prm-ot0 %%ot0-prm)))
  (define (maintainance-loop)
    (thread-sleep! (max background-period (ot0-background-period/lower-limit)))
    (begin-ot0-exclusive
     (when (ot0-up?) (%%checked maintainance (((on-ot0-maintainance) %%ot0-prm maintainance)) #f)))
     (maintainance-loop))
  ;; Should we lock?  No: Better document single-threadyness!
  (if (ot0-up?) (error "OT0 already running"))
  (let ((prm (make-ot0-prm #f udp (make-thread recv-loop 'ot0-receiver)))
        (nd (init #f now)))
    (if nd
        (begin
          (ot0-prm-ot0-set! prm nd) ;; let rec
          (set! %%ot0-prm prm) ;; ot0-up? => true
          ;; start handlers now
          (thread-start! (ot0-prm-incoming-thread prm))
          (thread-start! (make-thread maintainance-loop 'ot0-maintainance))
          #t)
        (begin
          #;(close-socket (ot0-prm-udp %%ot0-prm))
          #f))))

(define (ot0-node-destroy!)
  (if %%ot0-prm
      (let (#;(udp (ot0-prm-udp %%ot0-prm))
            (ref (ot0-prm-ot0 %%ot0-prm)))
        (set! %%ot0-prm #f)
        (begin-ot0-exclusive ((c-safe-lambda (ot0-node) void "ZT_Node_delete(___arg1);") ref))
        #;(close-socket udp))))

(define (ot0-up?) (and %%ot0-prm #t))

(define (ot0-address) ;; EXPORT
  (and (ot0-up?) ((c-lambda (ot0-node) unsigned-int64 "___return(ZT_Node_address(___arg1));") (ot0-prm-ot0 %%ot0-prm))))

(define (ot0-add-local-interface-address! sa) ;; EXPORT
  ;;; (unless (socket-address? sa) (error "ot0-add-local-interface-address!: illegal argument" sa))
  (assert-ot0-up! ot0-add-local-interface-address)
  (begin-ot0-exclusive
   ((OT0-c-safe-lambda
     (ot0-node ot0-socket-address) bool
     "___return(ZT_Node_addLocalInterfaceAddress(___arg1, ___arg2));")
    (ot0-prm-ot0 %%ot0-prm) sa)))

(define (ot0-clear-local-interface-address!) ;; EXPORT
  (assert-ot0-up! ot0-clear-local-interface-address!)
  (begin-ot0-exclusive
   ((OT0-c-safe-lambda (ot0-node) void "ZT_Node_clearLocalInterfaceAddresses(___arg1);") (ot0-prm-ot0 %%ot0-prm))))

(define (ot0-send! to type data) ;; EXPORT - send user message (u8vector)
  (define doit
    (OT0-c-safe-lambda
     (ot0-node unsigned-int64 unsigned-int64 scheme-object size_t) bool #<<END
     void *buf = ___CAST(void *,___BODY_AS(___arg4,___tSUBTYPED));
     ___return(ZT_Node_sendUserMessage(___arg1, NULL, ___arg2, ___arg3, buf, ___arg5));
END
))
  (assert-ot0-up! ot0-send!)
  (begin-ot0-exclusive
   (doit (ot0-prm-ot0 %%ot0-prm) to type data (u8vector-length data))))

(define (ot0-orbit moon #!optional (seed 0)) ;; EXPORT
  (define doit
    (OT0-c-safe-lambda
     (ot0-node unsigned-int64 unsigned-int64) bool
     "___return(ZT_Node_orbit(___arg1, NULL, ___arg2, ___arg3) == ZT_RESULT_OK);"))
  (assert-ot0-up! ot0-orbit)
  (begin-ot0-exclusive (doit (ot0-prm-ot0 %%ot0-prm) moon seed)))

(define (ot0-deorbit moon) ;; EXPORT
  (define deorbit
    (OT0-c-safe-lambda
     (ot0-node unsigned-int64) bool
     "___return(ZT_Node_deorbit(___arg1, NULL, ___arg2));"))
  (assert-ot0-up! ot0-deorbit)
  (begin-ot0-exclusive (deorbit (ot0-prm-ot0 %%ot0-prm) moon)))

(define (ot0-join network) ;; EXPORT
  (define dojoin (OT0-c-safe-lambda (ot0-node unsigned-int64) int "___return(ZT_Node_join(___arg1, ___arg2, NULL, NULL));"))
  (assert-ot0-up! ot0-join)
  (or
   (eqv? (begin-ot0-exclusive (dojoin (ot0-prm-ot0 %%ot0-prm) network)) 0)
   (error "ot0-join: failed for with rc" network rc)))

(define (ot0-leave network) ;; EXPORT
  (define doit (OT0-c-safe-lambda (ot0-node unsigned-int64) int "___return(ZT_Node_leave(___arg1, ___arg2, NULL, NULL));"))
  (assert-ot0-up! ot0-leave)
  (or (eqv? (begin-ot0-exclusive (doit network)) 0)
      (error "ot0-leave: failed for with rc" network rc)))

(define (ot0-multicast-subscribe network group #!optional (adi 0)) ;; EXPORT
  (define doit
    (OT0-c-safe-lambda
     (ot0-node unsigned-int64 unsigned-int64 unsigned-int64) int
     "___return(ZT_Node_multicastSubscribe(___arg1, NULL, ___arg2, ___arg3, ___arg4));"))
  (assert-ot0-up! ot0-multicast-subscribe)
  (or (eqv? (begin-ot0-exclusive (doit (ot0-prm-ot0 %%ot0-prm) network group adi)) 0)
      (error "ot0-multicast-subscribe: failed for with rc" network rc)))

(define (ot0-multicast-unsubscribe network group #!optional (adi 0)) ;; EXPORT
  (define doit
    (OT0-c-safe-lambda
     (ot0-node unsigned-int64 unsigned-int64 unsigned-int64) int
     "___return(ZT_Node_multicastUnsubscribe(___arg1, ___arg2, ___arg3, ___arg4));"))
  (assert-ot0-up! ot0-multicast-unsubscribe)
  (or (eqv? (begin-ot0-exclusive (doit (ot0-prm-ot0 %%ot0-prm) network group adi)) 0)
      (error "ot0-multicast-unsubscribe: failed for with rc" network rc)))

;;* Inspection

(define ot0-node-status
  (let ((bufsiz ((c-lambda () size_t "___return(sizeof(ZT_NodeStatus));")))
        (address (c-lambda (scheme-object) unsigned-int64
                           "___return(___CAST(ZT_NodeStatus *,___BODY_AS(___arg1,___tSUBTYPED))->address);"))
        (public (c-lambda (scheme-object) char-string
                          "___return((char*) ___CAST(ZT_NodeStatus *,___BODY_AS(___arg1,___tSUBTYPED))->publicIdentity);"))
        (private (c-lambda (scheme-object) char-string
                           "___return((char*) ___CAST(ZT_NodeStatus *,___BODY_AS(___arg1,___tSUBTYPED))->secretIdentity);"))
        (online (c-lambda (scheme-object) bool
                           "___return(___CAST(ZT_NodeStatus *,___BODY_AS(___arg1,___tSUBTYPED))->online);")))
    (lambda (#!optional k)
      (assert-ot0-up! ot0-node-status)
      (let ((buf (make-u8vector bufsiz)))
        ((c-lambda
          (ot0-node scheme-object) void
          "ZT_Node_status(___arg1, ___CAST(ZT_NodeStatus *,___BODY_AS(___arg2,___tSUBTYPED)));")
         (ot0-prm-ot0 %%ot0-prm) buf)
        (case k
          ((address) (address buf))
          ((public) (public buf))
          ((private) (private buf))
          ((online) (online buf))
          (else (public buf)))))))

(define ot0-peer-address (c-lambda (ot0-peer) unsigned-int64 "___return(___arg1->address);"))
(define ot0-peer-version
  (c-lambda
   (ot0-peer) char-string #<<END
   char buf[20] = "-";
   if(___arg1->versionMajor != -1) {
     snprintf(buf,20, "%d.%d.%d",___arg1->versionMajor, ___arg1->versionMinor, ___arg1->versionRev);
   }
   ___return(buf);
END
))
(define ot0-peer-latency (c-lambda (ot0-peer) int "___return(___arg1->latency);"))
(define ot0-peer-role
  (let ((numeric (c-lambda (ot0-peer) int "___return(___arg1->role);"))
        (roles '#(unit junction origin)))
    (lambda (peer) (vector-ref roles (numeric peer)))))
(define ot0-peer-path-count (c-lambda (ot0-peer) size_t "___return(___arg1->pathCount);"))
(define ot0-peer-had-aggregate-link (c-lambda (ot0-peer) bool "___return(___arg1->hadAggregateLink);"))
;; TODO accessors for `ZT_PeerPhysicalPath`
(define ot0-peer-n-path (c-lambda (ot0-peer size_t) ZT_PeerPhysicalPath  "___return(&___arg1->paths[___arg2]);"))
(define (ot0-peer-paths peer)
  (let ((len (ot0-peer-path-count peer)) (result '()))
    (do ((i 0 (+ i 1)))
        ((= i len) result)
      (set! result (cons (ot0-peer-n-path peer i) result)))))

(define (ot0-peerpath-address ppp)
  (let ((sockaddr #;(make-unspecified-socket-address)
                  (make-u8vector OT0_SOCKADDR_STORAGE_SIZE)))
    ((c-lambda
      (scheme-object ZT_PeerPhysicalPath) void #<<END
      memcpy(___BODY(___arg1), &___arg2->address, (sizeof(struct sockaddr_storage)));
END
) sockaddr ppp)
    #;(unless (or (internet6-socket-address? sockaddr) (internet-socket-address? sockaddr)) ;; DEBUG
            (error (debug sockaddr "ot0-peerpath-address: invalid address encountered") sockaddr))
    sockaddr))

(define ot0-peer-info->vector
  (let ((all (vector
              ot0-peer-address
              ot0-peer-version
              ot0-peer-latency
              ot0-peer-role
              ot0-peer-path-count
              ot0-peer-had-aggregate-link
              ;;ot0-peer-paths
              ;; (lambda (peer) (map ot0-peerpath-address (ot0-peer-paths peer)))
              (lambda (peer) (map (lambda (p) (%socket-address->string (ot0-peerpath-address p)))  (ot0-peer-paths peer)))
              )))
    (lambda (obj)
      (let* ((len (vector-length all)) (result (make-vector len)))
        (do ((i 0 (+ i 1)))
            ((= i len) result)
          (vector-set! result i ((vector-ref all i) obj)))))))

(define ot0-peers-map
  (let ((get (c-lambda (ot0-node) ot0-peers "___return(ZT_Node_peers(___arg1));"))
        (free (c-lambda (ot0-node ot0-peers) void "ZT_Node_freeQueryResult(___arg1, (void*)___arg2);"))
        (peer-n (c-lambda (ot0-peers size_t) ot0-peer "___return(&___arg1->peers[___arg2]);")))
    (lambda (proc)
      (assert-ot0-up! ot0-peers-map)
      (let* ((node (ot0-prm-ot0 %%ot0-prm))
             (all (get node)))
        (with-exception-catcher
         (lambda (ex) (free node all) (raise ex))
         (lambda ()
           (let ((n ((c-lambda (ot0-peers) size_t "___return(___arg1->peerCount);") all))
                 (result '()))
             (do ((i 0 (+ i 1)))
                 ((= i n)
                  (free node all)
                  result)
               (set! result (cons (proc (peer-n all i)) result))))))))))

(define (ot0-peers-info) (ot0-peers-map ot0-peer-info->vector))

;;** Config Accessors
(define ot0-virtual-config-nwid (c-lambda (ot0-virtual-config*) unsigned-int64 "___return(___arg1->nwid);"))
(define ot0-virtual-config-mac (c-lambda (ot0-virtual-config*) unsigned-int64 "___return(___arg1->mac);"))
(define ot0-virtual-config-name (c-lambda (ot0-virtual-config*) char-string "___return(___arg1->name);"))
(define (ot0-virtual-config-status cfg) ;; EXPORT
  (vector-ref
   '#(REQUESTING_CONFIGURATION OK ACCESS_DENIED NOT_FOUND PORT_ERROR CLIENT_TOO_OLD)
   ((c-lambda (ot0-virtual-config*) int "___return(___arg1->status);") cfg)))
(define ot0-virtual-config-public (c-lambda (ot0-virtual-config*) bool "___return(___arg1->type);"))
(define ot0-virtual-config-mtu (c-lambda (ot0-virtual-config*) size_t "___return(___arg1->mtu);"))
(define ot0-virtual-config-dhcp (c-lambda (ot0-virtual-config*) bool "___return(___arg1->dhcp);"))
(define ot0-virtual-config-bridge (c-lambda (ot0-virtual-config*) bool "___return(___arg1->bridge);"))
(define ot0-virtual-config-broadcast (c-lambda (ot0-virtual-config*) bool "___return(___arg1->broadcastEnabled);"))
(define ot0-virtual-config-porterror (c-lambda (ot0-virtual-config*) int "___return(___arg1->portError);"))
(define ot0-virtual-config-netconf-revision (c-lambda (ot0-virtual-config*) int "___return(___arg1->netconfRevision);"))
(define ot0-virtual-config-assigned-address-count
  (c-lambda (ot0-virtual-config*) size_t "___return(___arg1->assignedAddressCount);"))
(define ot0-virtual-config-route-count
  (c-lambda (ot0-virtual-config*) size_t "___return(___arg1->routeCount);"))
(define ot0-virtual-config-multicast-subscription-count
  (c-lambda (ot0-virtual-config*) size_t "___return(___arg1->multicastSubscriptionCount);"))

(define ot0-virtual-config-base->vector
  (let ((all (vector
              ot0-virtual-config-nwid
              ot0-virtual-config-mac
              ot0-virtual-config-name
              ot0-virtual-config-status
              ot0-virtual-config-public
              ot0-virtual-config-mtu
              ot0-virtual-config-dhcp
              ot0-virtual-config-bridge
              ot0-virtual-config-broadcast
              ot0-virtual-config-porterror
              ot0-virtual-config-netconf-revision
              ot0-virtual-config-assigned-address-count
              ot0-virtual-config-route-count
              ot0-virtual-config-multicast-subscription-count
              )))
    (lambda (obj)
      (let* ((len (vector-length all)) (result (make-vector len)))
        (do ((i 0 (+ i 1)))
            ((= i len) result)
          (vector-set! result i ((vector-ref all i) obj)))))))

;;** Query
(define (ZT_Node_freeQueryResult cfg) ;; Don't forget to free results!
  ((c-lambda (ot0-node void*) void "ZT_Node_freeQueryResult(___arg1, ___arg2);")
   (ot0-prm-ot0 %%ot0-prm) cfg))

(define (ot0-virtual-config*_release cfg) ;; INTERN Don't forget to free results!
  ((c-lambda (ot0-node ot0-virtual-config*) void "ZT_Node_freeQueryResult(___arg1, ___arg2);")
   (ot0-prm-ot0 %%ot0-prm) cfg))

(define (ot0-network-virtual-config* network) ;; INTERN
  (assert-ot0-up! ot0-VirtualNetworkConfig)
  ((c-lambda (ot0-node unsigned-int64) ot0-virtual-config* "___return(ZT_Node_networkConfig(___arg1, ___arg2));")
   (ot0-prm-ot0 %%ot0-prm) network))

(define (make-ot0-network-config-query accessor) ;; INTERN
  (lambda (network)
    (let ((cfg (ot0-network-virtual-config* network)))
      (and cfg
           (let ((result (accessor cfg)))
             (ot0-virtual-config*_release cfg)
             result)))))

(define ot0-query-network-mac (make-ot0-network-config-query ot0-virtual-config-mac)) ;; EXPORT
(define ot0-query-network-name (make-ot0-network-config-query ot0-virtual-config-name)) ;; EXPORT
(define ot0-query-network-status (make-ot0-network-config-query ot0-virtual-config-status)) ;; EXPORT
(define ot0-query-network-public (make-ot0-network-config-query ot0-virtual-config-public)) ;; EXPORT
(define ot0-query-network-mtu (make-ot0-network-config-query ot0-virtual-config-mtu)) ;; EXPORT
(define ot0-query-network-dhcp (make-ot0-network-config-query ot0-virtual-config-dhcp)) ;; EXPORT
(define ot0-query-network-bridge (make-ot0-network-config-query ot0-virtual-config-bridge)) ;; EXPORT
(define ot0-query-network-broadcast (make-ot0-network-config-query ot0-virtual-config-broadcast)) ;; EXPORT
(define ot0-query-network-porterror (make-ot0-network-config-query ot0-virtual-config-porterror)) ;; EXPORT
(define ot0-query-network-netconf-revision (make-ot0-network-config-query ot0-virtual-config-netconf-revision)) ;; EXPORT
(define ot0-query-network-assigned-address-count (make-ot0-network-config-query ot0-virtual-config-assigned-address-count)) ;; EXPORT
(define ot0-query-network-route-count (make-ot0-network-config-query ot0-virtual-config-route-count)) ;; EXPORT
(define ot0-query-network-multicast-subscription-count (make-ot0-network-config-query ot0-virtual-config-multicast-subscription-count)) ;; EXPORT

(define ot0-query-network-config-base->vector (make-ot0-network-config-query ot0-virtual-config-base->vector)) ;; EXPORT

;;* Utilities

(define ot0-network-mac->node ;; EXPORT
  (c-lambda
   (unsigned-int64 unsigned-int64) unsigned-int64 #<<END
   uint64_t node, nwid=___arg1, mac=___arg2;
   // This extracts a node address from a mac address.
   node = mac & 0xffffffffffull;
   node ^= ((nwid >> 8) & 0xff) << 32;
   node ^= ((nwid >> 16) & 0xff) << 24;
   node ^= ((nwid >> 24) & 0xff) << 16;
   node ^= ((nwid >> 32) & 0xff) << 8;
   node ^= (nwid >> 40) & 0xff;
   ___return(node);
END
))

(define ot0-network+node->mac ;; EXPORT
  (c-lambda
   (unsigned-int64 unsigned-int64) unsigned-int64 #<<END
 uint64_t mac, nwid=___arg1, node=___arg2;
 // We use LSB of network ID, and make sure that we clear
 // multicast and set local administration -- this is the first
 // octet of the 48 bit mac address.  We also avoid 0x52, which
 // is known to be used in KVM, libvirt, etc.
 mac = ((uint8_t)(nwid & 0xfe) | 0x02);
 if (mac == 0x52) {
  mac = 0x32;
 }
 mac <<= 40;
 mac |= node;
 // The rest of the network ID is XOR'd in, in reverse byte
 // order.
 mac ^= ((nwid >> 8) & 0xff) << 32;
 mac ^= ((nwid >> 16) & 0xff) << 24;
 mac ^= ((nwid >> 24) & 0xff) << 16;
 mac ^= ((nwid >> 32) & 0xff) << 8;
 mac ^= (nwid >> 40) & 0xff;
 ___return(mac);
END
))

(c-declare #<<c-declare-end

static inline uint64_t mac_from_vector(const void *src) // maybe better hwaddr instead of void
{
 const unsigned char *b = (const unsigned char *)src;
 uint64_t result;
 result = ((uint64_t)b[0] << 40)
  | ((uint64_t)b[1] << 32)
  | ((uint64_t)b[2] << 24)
  | ((uint64_t)b[3] << 16)
  | ((uint64_t)b[4] << 8)
  | (uint64_t)b[5];
 return result; // | ;-( highlithing confused with odd number of vertical bars here
}

static inline uint64_t g_zt_mac_hton(uint64_t mac)
{
 uint64_t result = 0;
 unsigned char *b = (unsigned char *)&result;
 b[0] = (unsigned char)((mac >> 40) & 0xff);
 b[1] = (unsigned char)((mac >> 32) & 0xff);
 b[2] = (unsigned char)((mac >> 24) & 0xff);
 b[3] = (unsigned char)((mac >> 16) & 0xff);
 b[4] = (unsigned char)((mac >> 8) & 0xff);
 b[5] = (unsigned char)(mac & 0xff);
 return result;
}

c-declare-end
)

(define (->ot0-mac x) ;; return a ZT uint64_t MAC encoding
  (cond
   ((u8vector? x)
    ((c-lambda
      (scheme-object) unsigned-int64
      "___return(mac_from_vector(___CAST(void *,___BODY_AS(___arg1,___tSUBTYPED))));")
     x))
   (else (error "->ot0-mac illegal argument" x))))

(define (ot0-mac->network x) ;; MAC encoding in network byte order (big endian)
  (cond
   ((fixnum? x)
    ((c-lambda
      (unsigned-int64) unsigned-int64
      "___return(g_zt_mac_hton(___arg1));")
     x))
   (else (error "ot0-mac->network illegal argument" x))))

(c-declare #<<c-declare-end
static inline uint64_t sockaddr_to_multicast_mac(struct sockaddr_storage *sa)
{
 uint64_t result;
 uint8_t *a=&((struct sockaddr_in6 *)sa)->sin6_addr;
 result = (0x33ll<<40|0x33ll<<32|0xffll<<24|(uint64_t)(a[13])<<16|(uint64_t)(a[14])<<8|a[15]); //|
 return result;
}

c-declare-end
)

(define %%ot0-socket-address6->nd6-multicast-mac
  (c-lambda (ot0-socket-address) unsigned-int64 "sockaddr_to_multicast_mac"))

(define gamsock-socket-address->nd6-multicast-mac
  (c-lambda (gamsock-socket-address) unsigned-int64 "sockaddr_to_multicast_mac"))

(c-declare #<<c-declare-end

void set_6plane_addr(struct sockaddr_in6 *sin6, uint64_t nwid, uint64_t zeroTierAddress, uint16_t port)
{
  nwid ^= (nwid >> 32);
  struct in6_addr *buf=&sin6->sin6_addr;
  //memset(buf, 0, sizeof(struct in6_addr));
  buf->s6_addr[0] = 0xfc;
  buf->s6_addr[1] = (uint8_t)(0xff&(nwid >> 24));
  buf->s6_addr[2] = (uint8_t)(0xff&(nwid >> 16));
  buf->s6_addr[3] = (uint8_t)(0xff&(nwid >> 8));
  buf->s6_addr[4] = (uint8_t)(0xff&nwid);
  buf->s6_addr[5] = (uint8_t)(0xff&(zeroTierAddress >> 32));
  buf->s6_addr[6] = (uint8_t)(0xff&(zeroTierAddress >> 24));
  buf->s6_addr[7] = (uint8_t)(0xff&(zeroTierAddress >> 16));
  buf->s6_addr[8] = (uint8_t)(0xff&(zeroTierAddress >> 8));
  buf->s6_addr[9] = (uint8_t)(0xff&zeroTierAddress);
  buf->s6_addr[10] = 0;
  buf->s6_addr[11] = 0;
  buf->s6_addr[12] = 0;
  buf->s6_addr[13] = 0;
  buf->s6_addr[14] = 0;
  buf->s6_addr[15] = 0x01;
  //sin6->sin6_len = sizeof(struct zts_sockaddr_in6);
  sin6->sin6_family = AF_INET6;
  sin6->sin6_port = htons(port);
  /*
  { int i;
    printf("Addr: ");
    for(i=0;i<14;i+=2) {
      printf("%02x%02x:", buf->s6_addr[i], buf->s6_addr[i+1]);
    }
    printf("%02x%02x\n", buf->s6_addr[i], buf->s6_addr[i+1]);
  }
  //*/
}
c-declare-end
)

;; (define p6 (make-6plane-addr #xff1d131d13000000 #x57707f31b6 7443))
;; (socket-address->internet6-address p6)

(define make-6plane-addr
  (let ((set-6plane-addr!
         (c-lambda
          (ot0-socket-address unsigned-int64 unsigned-int64 unsigned-int)
          void
          "set_6plane_addr(___arg1, ___arg2, ___arg3, ___arg4);")))
    (lambda (nwid node port)
      (let ((sa #;(internet6-address->socket-address
                 '#u8(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)
                 port 0 0)
             (%ot0-string->socket-address (string-append "::/" (number->string port)))))
        (set-6plane-addr! sa nwid node port)
        sa))))

(define (ot0-adhoc-network-id start #!optional (end start))
  ((c-lambda
    (unsigned-int unsigned-int) unsigned-int64
    "uint64_t r = 0xff00000000000000, s=(uint16_t)___arg1, e=(uint16_t)___arg2; ___return(r | (s << 40) | (e << 24));")
   start end))

(define (ot0-state-file-generator file-pattern base)
  (define (state-file objtype objid)
    (and base
         (let ((proc (vector-ref file-pattern objtype)))
           (and proc (proc base objid)))))
  (let loop ((p base) (sl (string-length base)))
    (if (or (eqv? (string-ref p (- sl 1)) #\/) (eqv? sl 0))
        (if (and (file-exists? p) (eq? (file-info-type (file-info p)) 'directory))
            (set! base p)
            (set base #f))
        (loop (string-append base "/") (+ sl 1))))
  state-file)

(let ((orig ot0-state-file-generator))
  (define (hexstr id digits)
    (let ((effective (number->string id 16)))
      (string-append (make-string (- digits (string-length effective)) #\0) effective)))

  (define file-pattern-default
    (vector
     (lambda (home id) (string-append home "lock")) ;; lock file (TODO tentative half implemented)
     (lambda (home id) (string-append home "name"))
     (lambda (home id) (string-append home "authentication"))
     (lambda (home id) (string-append home "origin"))
     (lambda (home id) (string-append home "junction/" (hexstr id 16)))
     (lambda (home id) (string-append home "unit/" (hexstr id 10)))
     (lambda (home id) (string-append home "network/" (hexstr id 16) ".conf"))
     (lambda (home id) (string-append home "network/" (hexstr id 16) ".local.conf"))
     ))

  (define file-pattern-zt
    (vector
     #f ;; _NULL
     (lambda (home id) (string-append home "identity.public"))
     (lambda (home id) (string-append home "identity.secret"))
     (lambda (home id) (string-append home "planet"))
     (lambda (home id) (string-append home "moons.d/" (hexstr id 16) ".moon"))
     (lambda (home id) (string-append home "peers.d/" (hexstr id 10) ".peer"))
     (lambda (home id) (string-append home "networks.d/" (hexstr id 16) ".conf"))
     (lambda (home id) (string-append home "networks.d/" (hexstr id 16) ".local.conf"))
     ))

  (define file-pattern-nng  ;; FIXME, wrong!
    (vector
     #f ;; _NULL
     (lambda (home id) (string-append home "identity.public"))
     (lambda (home id) (string-append home "identity.secret"))
     (lambda (home id) (string-append home "planet"))
     (lambda (home id) (string-append home "moon." (hexstr id 16) ))
     (lambda (home id) (string-append home "peers." (hexstr id 10)))
     (lambda (home id) (string-append home "networks.d/" (hexstr id 16) ".conf"))
     (lambda (home id) (string-append home "networks.d/" (hexstr id 16) ".local.conf"))
     ))

  (define (state-file-generator file-pattern base)
    (cond
     ((or (not file-pattern) (eqv? file-pattern 0)) (orig file-pattern-default base))
     ((eqv? file-pattern 1) (orig file-pattern-zt base))
     ((eqv? file-pattern 2) (orig file-pattern-nng base))
     ((number? file-pattern) (error "unknown file-pattern key" file-pattern))
     (else (orig file-pattern base))))

  (set! ot0-state-file-generator state-file-generator))

(define (ot0-make-default-state-handlers ot0-state-file)
  (define (pickup from)
    (and (file-exists? from)
         (let* ((size (file-size from))
                (data (make-u8vector size)))
           (call-with-input-file from (lambda (p) (read-subu8vector data 0 size p)))
           data)))
  (define (get objtype objid)
    (let ((from (ot0-state-file objtype objid)))
      (and from (pickup from))))
  (define (put objtype objid data)
    (let* ((into (ot0-state-file objtype objid))
           (was (and into (pickup into))))
      (if (and into (not (equal? was data)))
          (call-with-output-file into (lambda (p) #f (write-subu8vector data 0 (u8vector-length data) p))))))
  (values get put))

(include "ot0core-extensions.scm")
