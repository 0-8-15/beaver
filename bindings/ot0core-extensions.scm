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
   ((c-safe-lambda (ot0-node int char-string gamsock-socket-address) bool "zt_contact_peer")
    (ot0-prm-ot0 %%ot0-prm) lsock id addr))
  addr)

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
  (assert-ot0-up! ot0-set-config-item)
  (begin-ot0-exclusive
   ((c-lambda (ot0-node unsigned-int64 int unsigned-int64) bool "ZT_Node_setConfigItem")
    (ot0-prm-zt %%ot0-prm) nwid item value)))
|#
