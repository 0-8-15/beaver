;;; (C) 2020 JFW
;;;
;;; # Off Topic Null

(c-declare #<<END

#ifdef _WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
// # include <afunix.h>

/*
 * MinGW does not have sockaddr_un (yet)
 */

# ifndef UNIX_PATH_MAX
#  define UNIX_PATH_MAX 108
struct sockaddr_un {
  ADDRESS_FAMILY sun_family;
  char sun_path[UNIX_PATH_MAX];
};
# endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#endif

#include <time.h>

#include "ot0-hooks.h"

END
)

(define-macro (%max-u64) #xffffffffffffffff)

(c-define-type void* (pointer "void"))

(define (u8vector-copy-from-ptr! u8 u8o ptr ptro len)
  ;; TBD: Add range checks
  ((c-lambda
    (scheme-object size_t void* size_t size_t) scheme-object
    "memcpy(___CAST(char *,___BODY(___arg1)) + ___arg2, ___CAST(char *,___arg3) + ___arg4, ___arg5);
    ___return(___arg1);")
   u8 u8o ptr ptro len))

(define (u8vector/space? x size)
  (and (u8vector? x) (>= (u8vector-length x) size)))

;;; Time

(define ot0-now (c-lambda () unsigned-int64 "OT0_now"))

(define ot0-time->string
  (c-lambda
   (unsigned-int64) char-string
   "
static /* I DO NOT SEE WHY THIS SHOULD BE STATIC, but valgrind complains */
char buf[26] = {0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0};
 time_t tv =___arg1/1000;
#if WIN32
 _ctime64_s(&tv, 26, buf);
#else
 ctime_r(&tv, buf);
#endif
 ___return(buf);"))

;;; Crypto

(define OT0_C25519_PUBLIC_KEY_SIZE ((c-lambda () size_t "___return(OT0_C25519_PUBLIC_KEY_SIZE());")))
(define OT0_C25519_PRIVATE_KEY_SIZE ((c-lambda () size_t "___return(OT0_C25519_PRIVATE_KEY_SIZE());")))
(define OT0_C25519_SIGNATURE_SIZE ((c-lambda () size_t "___return(OT0_C25519_SIGNATURE_SIZE());")))
(define OT0_C25519_KEYPAIR_SIZE ((c-lambda () size_t "___return(OT0_C25519_KEYPAIR_SIZE());")))

(define (ot0-make-c25519-keypair) ;; EXPORT
  (let ((result (make-u8vector OT0_C25519_KEYPAIR_SIZE)))
    ((c-lambda (scheme-object) void "OT0_C25519_gen_kp(___BODY(___arg1));") result)
    result))

(define-macro (%ot0-u8vector-range-assert arg proc vec offset size)
  `(if (u8vector? ,vec)
       (or (>= (u8vector-length ,vec) ,size)
           (##raise-range-exception ,arg ',proc (u8vector-length ,vec) ,offset ,size))
       (error "illegal u8vector" ,proc ,arg ,vec)))

(define (c25519-keypair-secret-key kp) ;; EXPORT
  (%ot0-u8vector-range-assert 1 c25519-keypair-secret-key kp OT0_C25519_PUBLIC_KEY_SIZE OT0_C25519_PRIVATE_KEY_SIZE)
  (subu8vector kp OT0_C25519_PUBLIC_KEY_SIZE (u8vector-length kp)))

(define (ot0-C25519-key-agree! key pk sk) ;; EXPORT
  (unless (u8vector? key) (error "ot0-C25519-key-agree! illegal key" key))
  (%ot0-u8vector-range-assert 3 ot0-C25519-key-agree! sk 0 OT0_C25519_PRIVATE_KEY_SIZE)
  (%ot0-u8vector-range-assert 2 ot0-C25519-key-agree! pk 0 OT0_C25519_PUBLIC_KEY_SIZE)
  ((c-lambda
    (scheme-object scheme-object scheme-object size_t) void
    "OT0_C25519_key_agree(___BODY(___arg1), ___BODY(___arg2), ___BODY(___arg3), ___arg4);")
   sk pk key (u8vector-length key)))

(define (ot0-C25519-sign data pk sk) ;; EXPORT
  (unless (u8vector? data) (error "ot0-C25519-sign: can not sign" data))
  (%ot0-u8vector-range-assert 3 ot0-C25519-sign sk 0 OT0_C25519_PRIVATE_KEY_SIZE)
  (%ot0-u8vector-range-assert 2 ot0-C25519-sign pk 0 OT0_C25519_PUBLIC_KEY_SIZE)
  (let ((result (make-u8vector OT0_C25519_SIGNATURE_SIZE)))
    ((c-lambda
      (scheme-object scheme-object scheme-object size_t scheme-object) void
      "OT0_C25519_sign2(___BODY(___arg1), ___BODY(___arg2), ___BODY(___arg3), ___arg4, ___BODY(___arg5));")
     sk pk data (u8vector-length data) result)
    result))

(define (ot0-C25519-verify data sig pk) ;; EXPORT
  (unless (u8vector? data) (error "ot0-C25519-verify can not verify" data))
  (%ot0-u8vector-range-assert 2 ot0-C25519-verify sig 0 OT0_C25519_SIGNATURE_SIZE)
  (%ot0-u8vector-range-assert 3 ot0-C25519-verify pk 0 OT0_C25519_PUBLIC_KEY_SIZE)
  ((c-lambda
    (scheme-object scheme-object size_t scheme-object) bool
    "___return(OT0_C25519_verify(___BODY(___arg1), ___BODY(___arg2), ___arg3, ___BODY(___arg4)));")
   pk data (u8vector-length data) sig))

;;; Socket Address

(define OT0_SOCKADDR_STORAGE_SIZE ((c-lambda () size_t "___return(OT0_SOCKADDR_STORAGE_SIZE());")))
(define OT0_SOCKADDR_IN4_SIZE 8) ;; FIXME
(define OT0_SOCKADDR_IN6_SIZE 20) ;; FIXME

(c-define-type OT0-socket-address (pointer (struct "sockaddr_storage") socket-address))
(c-define-type OT0-nonnull-socket-address (nonnull-pointer (struct "sockaddr_storage") socket-address))

(define (%%ot0-socket-address? obj) (let ((f (foreign-tags obj))) (and f (eq? (car f) 'socket-address))))

(define (ot0-socket-address? obj)
  ;; TBD: remove deprecated, allocating version
  (or
   (u8vector/space? obj OT0_SOCKADDR_STORAGE_SIZE)
   (%%ot0-socket-address? obj)))

(define (ot0-socket-address->string addr) ;; EXPORT
  (cond
   ((u8vector/space? addr OT0_SOCKADDR_STORAGE_SIZE)
    ((c-lambda
      (scheme-object) char-string
      "char buf[64]; OT0_sockaddr_into_string(___BODY(___arg1), buf); ___return(buf);")
     addr))
   ((u8vector? addr) (error "socket-address->string: u8vector too short"))
   (else
    ((c-lambda
      (OT0-socket-address) char-string
      "char buf[64]; OT0_sockaddr_into_string(___arg1, buf); ___return(buf);")
     addr))))

(define ot0-string->socket-address1 ;; MUST be freed!
  ;; FIXME: use a better version without malloc instead!
  (let ((free (c-lambda (OT0-nonnull-socket-address) void "OT0_free_sockaddr")))
    (lambda (str)
      (let ((result ((c-lambda (char-string) OT0-socket-address "OT0_sockaddr_from_string") str)))
        (make-will result free)
        result))))

(define (ot0-string->socket-address str)
  (let ((result (make-u8vector OT0_SOCKADDR_STORAGE_SIZE)))
    ((c-lambda
      (scheme-object char-string) void
      "OT0_init_sockaddr_from_string(___BODY(___arg1), ___arg2);")
     result str)
    result))

(define ot0-internetX-address->socket-address1 ;; deprecated
  (let ((free (c-lambda (OT0-nonnull-socket-address) void "OT0_free_sockaddr"))
        (build (c-lambda
                (scheme-object size_t unsigned-int16) OT0-socket-address
                "___return(OT0_sockaddr_from_bytes_and_port(___BODY(___arg1),___arg2,___arg3));")))
    (lambda (host port)
      (let ((result (build host (u8vector-length host) port)))
        (make-will result free)
        result))))

(define ot0-internetX-address->socket-address
  (let ()
    (define build!
      (c-lambda
       (scheme-object scheme-object size_t unsigned-int16) OT0-socket-address
       "OT0_init_sockaddr_from_bytes_and_port(___BODY(___arg1), ___BODY(___arg2),___arg3,___arg4);"))
    (lambda (host port)
      (let ((result (make-u8vector OT0_SOCKADDR_STORAGE_SIZE)))
        (build! result host (u8vector-length host) port)
        result))))

(define (ot0-socket-address-family sa)
  (cond
   ((u8vector/space? sa 1)
    ((c-lambda (scheme-object) int "___return(___CAST(struct sockaddr_storage*, ___BODY(___arg1))->ss_family);") sa))
   (else ((c-lambda (OT0-nonnull-socket-address) int "___return(___arg1->ss_family);") sa))))

(define (ot0-socket-address-family-set! sa fam)
  (cond
   ((u8vector/space? sa 1)
    ((c-lambda (scheme-object int) void
               "___CAST(struct sockaddr_storage*, ___BODY(___arg1))->ss_family = ___arg2;") sa fam))
   (else ((c-lambda (OT0-nonnull-socket-address int) void "___arg1->ss_family = ___arg2;") sa fam))))

(define (ot0-socket-address4-port sa4)
  (cond
   ((u8vector/space? sa OT0_SOCKADDR_IN4_SIZE)
    ((c-lambda (scheme-object) unsigned-int "___CAST(struct sockaddr_in*, ___BODY(___arg1))->sin_port;") sa4))
   (else
    ((c-lambda
      (OT0-nonnull-socket-address) unsigned-int
      "___return(ntohs(___CAST(struct sockaddr_in *, ___arg1)->sin_port));") sa4))))

(define (ot0-socket-address4-ip4addr sa)
  (let ((result (make-u8vector 4)))
    (cond
     ((u8vector/space? sa OT0_SOCKADDR_IN4_SIZE)
      ((c-lambda
        (scheme-object scheme-object) void
        "memcpy(___BODY(___arg2), &(___CAST(struct sockaddr_in*, ___BODY(___arg1))->sin_addr), 4);")
       sa result))
     (else
      ((c-lambda
        (OT0-nonnull-socket-address scheme-object) void
        "memcpy(___BODY(___arg2), &(((struct sockaddr_in *)___arg1)->sin_addr), 4);")
       sa result)))
    result))

(define (ot0-socket-address6-port sa)
  (cond
   ((u8vector/space? sa OT0_SOCKADDR_IN6_SIZE)
    ((c-lambda
      (scheme-object) unsigned-int
      "___return(ntohs(___CAST(struct sockaddr_in6 *, ___BODY(___arg1))->sin6_port));")
     sa))
   (else
    ((c-lambda
      (OT0-nonnull-socket-address) unsigned-int
      "___return(ntohs(___CAST(struct sockaddr_in6 *, ___arg1)->sin6_port));")
     sa))))

(define (ot0-socket-address6-flowinfo sa)
  (cond
   ((u8vector/space? sa OT0_SOCKADDR_IN6_SIZE)
    ((c-lambda
      (scheme-object) int
      "___return(___CAST(struct sockaddr_in6 *, ___BODY(___arg1))->sin6_flowinfo);")
     sa))
   (else
    ((c-lambda
      (OT0-nonnull-socket-address) int
      "___return(___CAST(struct sockaddr_in6 *, ___arg1)->sin6_flowinfo);")
     sa))))

(define (ot0-socket-address6-scope sa)
  (cond
   ((u8vector/space? sa OT0_SOCKADDR_IN6_SIZE)
    ((c-lambda
      (scheme-object) int
      "___return(___CAST(struct sockaddr_in6 *, ___BODY(___arg1))->sin6_scope_id);")
     sa))
   (else
    ((c-lambda
      (OT0-nonnull-socket-address) int
      "___return(___CAST(struct sockaddr_in6 *, ___arg1)->sin6_scope_id);")
     sa))))

(define (ot0-socket-address6-ip6addr sa)
  (let ((result (make-u8vector 16)))
    (cond
     ((u8vector/space? sa OT0_SOCKADDR_IN6_SIZE)
      ((c-lambda
        (scheme-object scheme-object) void
        "memcpy(___BODY(___arg2), &(((struct sockaddr_in6 *)___BODY(___arg1))->sin6_addr), 16);")
       sa result))
     (else
      ((c-lambda
        (OT0-nonnull-socket-address scheme-object) void
        "memcpy(___BODY(___arg2), &(((struct sockaddr_in6 *)___arg1)->sin6_addr), 16);")
       sa result)))
    result))

;;; Network Identifier

(c-define-type ot0-id (type "OT0_Id" ot0-id))

(define (ot0-generate-id) ;; EXPORT
  ;;; BEWARE: The underlying code claims this may take time.  So far it does not.
  ;;;
  ;;(print "Generating key...")
  (let ((result ((c-lambda () ot0-id "OT0_generate_Id"))))
    ;;(println "done.")
    (make-will result (c-lambda (ot0-id) void "OT0_g_free_ID"))
    result))

(define (string->ot0-id str) ;; EXPORT
  (let ((result ((c-lambda (char-string) ot0-id "OT0_new_Id_from_string") str)))
    (make-will result (c-lambda (ot0-id) void "OT0_g_free_ID"))
    result))

(define (ot0-id->string id #!optional (include-private #f)) ;; EXPORT
  ((c-lambda (ot0-id bool) char-string "
char buf[384]; //ZT_IDENTITY_STRING_BUFFER_LENGTH
OT0_Id_to_string(___arg1, ___arg2, buf);
___return(buf);")
   id include-private))

(define (ot0-id-pk obj) ;; EXPORT
  (let ((result (make-u8vector OT0_C25519_PUBLIC_KEY_SIZE)))
    (u8vector-copy-from-ptr!
     result 0
     ((c-lambda (ot0-id) void* "OT0_ID_pk") obj) 0
     OT0_C25519_PUBLIC_KEY_SIZE)
    result))

(define (ot0-id-kp obj) ;; EXPORT
  (let ((result (make-u8vector OT0_C25519_KEYPAIR_SIZE)))
    ((c-lambda (ot0-id scheme-object) void "OT0_ID_kp_into(___arg1, ___BODY(___arg2));") obj result)
    result))

;;; Vertex

(c-define-type ot0-vertex (type "OT0_VERTEX" ot0-vertex))

(define (ot0-vertex? obj) (and (foreign? obj) (let ((f (foreign-tags obj))) (and f (eq? (car f) 'ot0-vertex)))))

(define ot0-vertex-free! (c-lambda (ot0-vertex) void "OT0_free_vertex"))

(define %u8vector->ot0-vertex
  (c-lambda
   (scheme-object size_t unsigned-int) ot0-vertex
   "___return(OT0_u8_to_vertex(___BODY(___arg1), ___arg2, ___arg3));"))

(define (u8vector->ot0-vertex u8 #!optional (off 0)) ;; EXPORT
  (let ((result (%u8vector->ot0-vertex u8 (u8vector-length u8) off)))
    (make-will result ot0-vertex-free!)
    result))

(define (ot0-vertex->u8vector obj #!optional (kind #f)) ;; EXPORT
  (let* ((buf ((c-lambda (ot0-vertex bool) void* "OT0_vertex_serialize") obj kind))
         (len ((c-lambda (void*) size_t "OT0_Buffer_length") buf))
         (result (make-u8vector len)))
    (u8vector-copy-from-ptr!
     result 0
     ((c-lambda (void*) void* "OT0_Buffer_data") buf) 0
     len)
    ((c-lambda (void*) void "OT0__free_vertex_buffer") buf)
    result))

(define ot0-vertex= (c-lambda (ot0-vertex ot0-vertex) bool "OT0_vertex_equal_p")) ;; EXPORT

(define ot0-vertex-type* (c-lambda (ot0-vertex) unsigned-int "OT0_vertex_type"))
(define (ot0-vertex-type obj) ;; EXPORT
  (case (ot0-vertex-type* obj)
    ((0) 'NULL)
    ((1) 'origin)
    ((127) 'junction)
    (else 'error)))

(define ot0-vertex-id (c-lambda (ot0-vertex) unsigned-int64 "OT0_vertex_id")) ;; EXPORT
(define ot0-vertex-timestamp (c-lambda (ot0-vertex) unsigned-int64 "OT0_vertex_timestamp")) ;; EXPORT

(define (ot0-vertex-signature obj) ;; EXPORT
  (let ((result (make-u8vector OT0_C25519_SIGNATURE_SIZE)))
    ((c-lambda
      (scheme-object ot0-vertex) void
      "OT0_vertex_signature_into(___BODY(___arg1), ___arg2);")
     result obj)
    result))

(define (ot0-vertex-update-pk obj) ;; EXPORT
  (let ((result (make-u8vector OT0_C25519_PUBLIC_KEY_SIZE)))
    ((c-lambda
      (scheme-object ot0-vertex) void
      "OT0_vertex_updatepk_into(___BODY(___arg1), ___arg2);")
     result obj)
    result))

(define ot0-vertex-replacement? ;; EXPORT
  (c-lambda (ot0-vertex ot0-vertex) bool "OT0_vertex_replacement_p"))

;;; TODO FIXME: rename `roots` into `replicates`?!?!

(define ot0-vertex-roots (c-lambda (ot0-vertex) size_t "OT0_vertex_roots"))
(define ot0-vertex/root-id (c-lambda (ot0-vertex size_t) ot0-id "OT0_root_id"))
(define ot0-vertex/root-endpoints (c-lambda (ot0-vertex size_t) size_t "OT0_root_endpoints"))
(define ot0-vertex/root-endpoint (c-lambda (ot0-vertex size_t size_t) OT0-socket-address "OT0_root_endpoint"))

(c-define-type ot0-roots (type "OT0_ROOTS"))

(define ot0-make-roots
  (let ((free (c-lambda (ot0-roots) void "OT0_free_roots")))
    (lambda ()
      (let ((result ((c-lambda () ot0-roots "OT0_make_roots"))))
        (make-will result free)
        result))))
(define ot0-roots-length (c-lambda (ot0-roots) size_t "OT0_roots_length"))
(define ot0-roots-add! (c-lambda (ot0-roots ot0-id) size_t "OT0_add_root"))
(define ot0-roots-add-endpoint! (c-lambda (ot0-roots size_t OT0-socket-address) size_t "OT0_add_root_endpoint"))

(define (ot0-vertex-edges obj #!optional (filter (lambda (x) #t)))
  (define (ot0-edge-addresses obj n)
    (define result '())
    (let ((m (ot0-vertex/root-endpoints obj n)))
      (do ((i 0 (+ i 1)))
          ((eqv? i m) result)
        (let ((sa (ot0-vertex/root-endpoint obj n i)))
          (receive
           (addr port)
           (case (socket-address-family sa)
             ((2) (values (socket-address4-ip4addr sa) (socket-address4-port sa)))
             ((10) (values (socket-address6-ip6addr sa) (socket-address6-port sa)))
             (else (values #f #f)))
           (set! result (cons (list addr port) result)))))))
  (let ((n (ot0-vertex-roots obj))
        (result '()))
    (do ((i 0 (+ 1 i)))
        ((eqv? i n) (reverse! result))
      (set! result
            (cons (cons (ot0-id->string (ot0-vertex/root-id obj i) #f)
                        (ot0-edge-addresses obj i))
                  result)))))

(define %ot0-make-vertex
  ;;(type nr roots timestamp update-pk signature-kp)
  (c-lambda
   (unsigned-int64 unsigned-int ot0-roots unsigned-int64 scheme-object scheme-object scheme-object)
   ot0-vertex "___return(OT0_make_vertex(___arg1, ___arg2, ___arg3, ___arg4,
 ___BODY(___arg5), ___BODY(___arg6), ___BODY(___arg7)));"))

(define ot0-make-vertex*
  (let ((free (c-lambda (ot0-vertex) void "OT0_free_vertex")))
    (define (ot0-make-vertex0 nr type roots timestamp update-pk signature-pk signature-sk)
      (%ot0-make-vertex
       nr
       (case type
         ((origin 1) 1)
         ((junction 127) 127)
         (else (error "illegal vertex type" type)))
       roots
       timestamp
       update-pk
       signature-pk signature-sk))
    (lambda (nr type roots timestamp update-pk signature-pk signature-sk)
      (let ((result (ot0-make-vertex0 nr type roots timestamp update-pk signature-pk signature-sk)))
        (make-will result free)
        result))))

(define (ot0-make-vertex/options options)
  (let ((nr #f)
        (type 'junction)
        (roots (ot0-make-roots))
        (timestamp (ot0-now))
        (update-pk #f)
        (signature-pk #f)
        (signature-sk #f)
        ;; options
        (check-result #t))
    (define (add-root root)
      #; (id-string endpoint ...)
      (let* ((id (string->ot0-id (car root)))
             (idx (ot0-roots-add! roots id)))
        (for-each
         (lambda (endpoint)
           (let ((addr (cond
                         ((string? endpoint) (ot0-string->socket-address endpoint))
                        (else (error "ot0-make-vertex: illegal endpoint" endpoint)))))
             (ot0-roots-add-endpoint! roots idx addr)))
         (cdr root))))
    (define (set-pk! val offset)
      (unless update-pk (set! update-pk val))
      (set! signature-pk val))
    (define (raise-illegal-argument-for-keyword key val)
      (error "ot0-make-vertex: illegal argument to keyword" key val))
    (define (finally-compose-vertex)
      (ot0-make-vertex* nr type roots timestamp update-pk signature-pk signature-sk))
    (let loop ((arg 1) (options options))
      (if (null? options)
          (cond
           ((not nr) (error "ot0-make-vertex: missing hash code"))
           ((not update-pk) (error "ot0-make-vertex: missing update public key"))
           ((not signature-pk) (error "ot0-make-vertex: missing signature public key"))
           ((not signature-sk) (error "ot0-make-vertex: missing signature secret key"))
           ((not check-result) (finally-compose-vertex))
           (else
            (let ((result (finally-compose-vertex)))
              (unless
               (ot0-C25519-verify
                (ot0-vertex->u8vector result #t)
                (ot0-vertex-signature result)
                (ot0-vertex-update-pk result))
               (error "ot0-make-vertex: result signature did not verify"))
              (unless
               (let* ((data (ot0-vertex->u8vector result))
                      (results-real-part (u8vector->ot0-vertex data)))
                 (ot0-vertex= result results-real-part))
               (error "ot0-make-vertex: result serialization round trip failed"))
              result)))
          (if (null? (cdr options))
              (error "ot0-make-vertex: odd number of arguments")
              (let ((val (cadr options)))
                (case (car options)
                  ((type:) (set! type val))
                  ((nonce:)
                   (unless (number? val)
                           (##raise-range-exception arg ot0-make-vertex nonce: val))
                   (let ((val (inexact->exact val)))
                     (unless (and (>= val 0) (<= val (%max-u64)))
                             (##raise-range-exception arg ot0-make-vertex nonce: val))
                     (set! nr val)))
                  ((timestamp:)
                   (let ((val (inexact->exact val)))
                     (unless (and (>= val 0) (<= val (%max-u64)))
                             (##raise-range-exception arg ot0-make-vertex timestamp: val))
                     (set! timestamp val)))
                  ((update-pk:)
                   #;(TODO: warn "(when update-pk ...?)")
                   (%ot0-u8vector-range-assert arg ot0-make-vertex val 0 OT0_C25519_PUBLIC_KEY_SIZE)
                   (set! update-pk val))
                  ((pk:)
                   (%ot0-u8vector-range-assert arg ot0-make-vertex val 0 OT0_C25519_PUBLIC_KEY_SIZE)
                   (set-pk! val 0))
                  ((sk:)
                   (%ot0-u8vector-range-assert arg ot0-make-vertex val 0 OT0_C25519_PRIVATE_KEY_SIZE)
                   (set! signature-sk val))
                  ((kp: keypair:)
                   (%ot0-u8vector-range-assert arg ot0-make-vertex val OT0_C25519_PUBLIC_KEY_SIZE OT0_C25519_PRIVATE_KEY_SIZE)
                   (set-pk! val 0)
                   (set! signature-sk (c25519-keypair-secret-key val)))
                  ((roots: replicates:)
                   (unless (or (null? val) (pair? val))
                           (raise-illegal-argument-for-keyword (car options) val))
                   (for-each
                    (lambda (r)
                      (unless (and (pair? r) (string? (car r)))
                              (raise-illegal-argument-for-keyword (car options) val)))
                    val)
                   (for-each add-root val))
                  ((check-result:)
                   (set! check-result
                         (case val
                           ((#f) #f)
                           ((#t) #t)
                           ((false false: no no:) #f)
                           ((true true: yes yes:) #t)
                           (else #t))))
                  (else (error "ot0-make-vertex: unhandled key" (car options))))
                (loop (+ arg 2) (cddr options))))))))

(define (ot0-make-vertex . options) ;; EXPORT
  (ot0-make-vertex/options options))

(define (ot0-display-vertex obj) ;; EXPORT
  (define (ot0-display-root obj n)
    (display (ot0-id->string (ot0-vertex/root-id obj n) #t))
    (let ((m (ot0-vertex/root-endpoints obj n)))
      (display #\space) (display m) (display " addresses:")
      (do ((i 0 (+ i 1)))
          ((eqv? i m)
           (newline))
        (display "\n  ")
        (display (ot0-socket-address->string (ot0-vertex/root-endpoint obj n i))))))
  (display "Vertex Type: ")
  (display (ot0-vertex-type obj))
  (display " nonce: ")
  (display (number->string (ot0-vertex-id obj) 16))
  (display " timestamp: ")
  (display (ot0-time->string (ot0-vertex-timestamp obj)))
  (newline)
  (display "Sig: ")
  (display (ot0-vertex-signature obj))
  (newline)
  (display "Update PK: ")
  (display (ot0-vertex-update-pk obj))
  (newline)
  (let ((n (ot0-vertex-roots obj)))
    (display "edges: ") (display n) (newline)
    (do ((i 0 (+ 1 i)))
        ((eqv? i n))
      (ot0-display-root obj i)))
  (newline))

(define (ot0-parameter-int-set! key value)
  ((c-lambda (int int64) bool "OT0_parameter_int_set")
   (case key
     ((PING_CHECK) 1)
     (else (error "invalid OT0 int parameter name" key)))
   value))

(define (ot0-parameter-function-set! key value)
  ;; FIXME the `function` delcaration is stupid, but gambit did not
  ;; eat plain `function` as expected.
  ((c-lambda (int (function () bool)) bool "OT0_parameter_pointer_set")
   (case key
     ((INCOMING_PACKET_FILTER) 3)
     (else (error "invalid OT0 pointer parameter name" key)))
   value))

(include "ot0core.scm")

(define (ot0-vertex-contact-all-edges! vertex)
  (let ((origin-edges (ot0-vertex-edges vertex)))
    (for-each
     (lambda (edge)
       (for-each
        (lambda (addr)
          (ot0-contact-peer (car edge) (apply internetX-address->socket-address addr)))
        (cdr edge)))
     origin-edges)))

(ot0core-socket-address->string-set! ot0-socket-address->string)
;; FIXME: use a better version without malloc instead!
(ot0core-string->socket-address-set! ot0-string->socket-address)
