;;* Extensions

;; These require changes to ot0 core code.

(c-declare #<<c-declare-end
extern enum ZT_ResultCode
 ZT_Node_contact_peer(ZT_Node *node, void *tptr, unsigned int port,
                      const char* id, const struct sockaddr_storage *addr, int64_t now);

static int zt_contact_peer(ZT_Node *zt_node, int lsock, const char* id, const struct sockaddr_storage *addr)
{
 return ZT_Node_contact_peer(zt_node, NULL, lsock, id, addr, zt_now()) == ZT_RESULT_OK;
}
c-declare-end
)

(define (ot0-contact-peer id addr #!optional (lsock 0))
  (assert-ot0-up! ot0-contact-peer)
  (begin-ot0-exclusive
   ((cond-expand
     (gamsock-socket-address-is-u8vector
      (c-safe-lambda
       (ot0-node int nonnull-char-string scheme-object) bool
       "___return(zt_contact_peer(___arg1,___arg2,___arg3,___BODY(___arg4)));"))
     (else
      (c-safe-lambda (ot0-node int nonnull-char-string gamsock-socket-address) bool "zt_contact_peer")))
    (ot0-prm-ot0 %%ot0-prm) lsock id addr))
  addr)

(c-declare #<<c-declare-end
extern enum ZT_ResultCode
 ZT_Node_request_whois(ZT_Node *node, void *tptr, uint64_t addr);

static int ot0_request_whois(ZT_Node *zt_node, uint64_t addr)
{
 return ZT_Node_request_whois(zt_node, NULL, addr) == ZT_RESULT_OK;
}
c-declare-end
)

(define (ot0-request-whois id)
  (assert-ot0-up! ot0-request-whois)
  (begin-ot0-exclusive
   ((c-safe-lambda (ot0-node unsigned-int64) bool "ot0_request_whois")
    (ot0-prm-ot0 %%ot0-prm) id)))

(c-define
 (ot0-incoming-packet node userptr term peer)
 (ot0-node void* int void*)
 bool "scm_ot0_incomming_packet_cb" "static"
 (let ()
   (define (pkt-term e)
     (case e ;; MUST match Packet.hpp
       ((0) 'NOP)
       ((1) 'HELLO)
       ((2) 'ERROR)
       ((3) 'OK)
       ((4) 'WHOIS)
       ((5) 'RENDEZVOUS)
       ((6) 'FRAME)
       ((7) 'EXT_FRAME)
       ((8) 'ECHO)
       ((9) 'MULTICAST_LIKE)
       ((#xa) 'NETWORK_CREDENTIALS)
       ((#xb) 'NETWORK_CONFIG_REQUEST)
       ((#xc) 'NETWORK_CONFIG)
       ((#xd) 'MULTICAST_GATHER)
       ((#xe) 'MULTICAST_FRAME)
       ((#xf) 'unused)
       ((#10) 'PUSH_DIRECT_PATHS)
       ((#x11) 'deprecated)
       ((#x12) 'ACK)
       ((#x13) 'QOS_MEASUREMENT)
       ((#x14) 'USER_MESSAGE)
       ((#x15) 'REMOTE_TRACE)
      (else (cons 'PKT e))))
   (cond
    ((procedure? (on-ot0-incoming-packet))
     (%%checked ot0-incoming-packet ((on-ot0-incoming-packet) node userptr (pkt-term term) peer) #t))
    (else (debug 'ot0-incoming-packet "this should never happen!") #t))))

(define on-ot0-incoming-packet ;; EXPORT HOOK - incoming packets
  (let ((val #f))
    (case-lambda
     (() val)
     ((x)
      (if (procedure? x)
          (begin
            (set! val x)
            (ot0-parameter-function-set! 'INCOMING_PACKET_FILTER ot0-incoming-packet))
          (begin
            (set! val #f)
            (ot0-parameter-function-set! 'INCOMING_PACKET_FILTER #f)))))))

#|
;; Might be usedful.
bool ZT_Node_setConfigItem(ZT_Node* node, uint64_t nwid, int item, uint64_t value)
{
  try {
    ZeroTier::SharedPtr<ZeroTier::Network> net = reinterpret_cast<ZeroTier::Node *>(node)->network(nwid);
    if(!net->hasConfig()) {
      fprintf(stderr, "ZT_Node_setConfigItem: network %xll has no config\n", nwid);
      return false;
    }
    ZeroTier::NetworkConfig &cfg = (ZeroTier::NetworkConfig &) net->config();
    // Hm. FIXME.  Maybe this would need locking.  Function first, it's an experiment.
    switch(item) {
    case 1: cfg.mtu = value; return true;
    case 2: cfg.multicastLimit = value; return true;
    }
    return false;
  } catch ( ... ) {
    return false;
  }
}
;;; ------

(c-declare "extern bool ZT_Node_setConfigItem(ZT_Node* node, uint64_t nwid, int item, uint64_t value);")

(define (ot0-set-config-item! nwid item value)
  (assert-ot0-up! ot0-set-config-item!)
  (begin-ot0-exclusive
   ((c-lambda (ot0-node unsigned-int64 int unsigned-int64) bool "ZT_Node_setConfigItem")
    (ot0-prm-zt %%ot0-prm) nwid item value)))
|#
