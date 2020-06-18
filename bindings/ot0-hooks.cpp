#include "ot0-hooks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <algorithm>

#include <node/Constants.hpp>
#include <node/World.hpp>
#include <node/C25519.hpp>
#include <node/Identity.hpp>
#include <node/InetAddress.hpp>
#include <osdep/OSUtils.hpp>

using namespace ZeroTier;

uint64_t OT0_now() { return OSUtils::now(); }

OT0_Buffer OT0__make_vertex_buffer() {
  return new Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>();
}

void OT0__free_vertex_buffer(OT0_Buffer x) {
  delete (Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>*)x;
}

size_t OT0_Buffer_length(void* b) {
  return ((Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>*)b)->size();
}

void* OT0_Buffer_data(void* b) {
  return ((Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>*)b)->unsafeData();
}

size_t OT0_SOCKADDR_STORAGE_SIZE() { return sizeof(struct sockaddr_storage); };

// Crypto

size_t OT0_C25519_PUBLIC_KEY_SIZE() { return ZT_C25519_PUBLIC_KEY_LEN; }
size_t OT0_C25519_PRIVATE_KEY_SIZE() { return ZT_C25519_PRIVATE_KEY_LEN; }
size_t OT0_C25519_SIGNATURE_SIZE() { return ZT_C25519_SIGNATURE_LEN; }
size_t OT0_C25519_KEYPAIR_SIZE() { return sizeof(C25519::Pair); }

void OT0_C25519_gen_kp(void* into) { *((C25519::Pair*)into) = C25519::generate(); }
void OT0_C25519_key_agree(void* sk, void* pk, void* key, size_t size) {
  C25519::agree(*(C25519::Private*)sk, *(C25519::Public*)pk, key, size);
}

void OT0_C25519_sign2(const void* sk, const void* pk, const void* buffer, size_t size, void* result) {
  C25519::sign(*(C25519::Private*) sk, *(C25519::Public*) pk, buffer, size, ((C25519::Signature*)result));
}

bool OT0_C25519_verify(const void* pk, const void* buffer, size_t size, const void* signature) {
  return C25519::verify(*(C25519::Public*) pk, buffer, size, *(C25519::Signature*)signature);
}

// Identifier

void OT0_sockaddr_into_string(const void* sa, char buf[64]) { ((InetAddress*)sa)->toString(buf); }

void* OT0_sockaddr_from_string(const char* str) { return new InetAddress(str); }
void OT0_free_sockaddr(void* addr) { delete ((InetAddress*) addr); }
void* OT0_sockaddr_from_bytes_and_port(const void* data, size_t len, unsigned int port)
{ return new InetAddress(data, len, port); }
void OT0_init_sockaddr_from_bytes_and_port(void *into, const void* data, size_t len, unsigned int port)
{ *((InetAddress*) into) = InetAddress(data, len, port); }

void OT0_g_free_ID(OT0_Id id) { delete (Identity*)id; }

OT0_Id OT0_generate_Id() { Identity* result = new Identity(); result->generate(); return result; }
OT0_Id OT0_new_Id_from_string(const char*str) { return new ZeroTier::Identity(str); }
void OT0_Id_to_string(OT0_Id id, bool include_private, char* buf) {
  ((Identity*)id)->toString(include_private, buf);
};
const void* OT0_ID_pk(OT0_Id id) { return ((Identity*)id)->publicKey().data; }
void OT0_ID_kp_into(OT0_Id id, void* result) { *((C25519::Pair*)result) = ((Identity*)id)->privateKeyPair();  }

// Roots

OT0_ROOTS OT0_make_roots() { return new std::vector<World::Root>; }
void OT0_free_roots(OT0_ROOTS roots) { delete (std::vector<World::Root>*) roots;}
size_t OT0_add_root(OT0_ROOTS roots, OT0_Id id) {
  std::vector<World::Root>* r = (std::vector<World::Root>*)roots;
  size_t result = r->size();
  r->push_back(World::Root());
  r->back().identity=*((Identity*)id);
  return result;
}

size_t OT0_roots_length(OT0_ROOTS roots) { return ((std::vector<World::Root>*) roots)->size(); }

size_t OT0_add_root_endpoint(OT0_ROOTS roots, size_t i, const void* addr) {
  std::vector<World::Root>* rv = (std::vector<World::Root>*)roots;
  World::Root* r=&(*rv)[i];
  size_t result = r->stableEndpoints.size();
  r->stableEndpoints.push_back(*((InetAddress*)addr));
  return result;
}

// Vertex/Planet

OT0_VERTEX OT0_make_vertex(uint64_t id, unsigned int type, void* roots, uint64_t ts, void* update_pk, void* sign_pk, void* sign_sk) {
  C25519::Pair signWith;
  C_memcpy(&signWith.pub.data, sign_pk, ZT_C25519_PUBLIC_KEY_LEN);
  C_memcpy(&signWith.priv.data, sign_sk, ZT_C25519_PRIVATE_KEY_LEN);
  World *result = new World();
  World::Type ctype = type==1 ? World::Type::TYPE_PLANET : type==127 ? World::Type::TYPE_MOON : World::Type::TYPE_NULL;
  *result = World::make(ctype, id, ts, *(C25519::Public*)update_pk, *(std::vector<World::Root>*)roots, signWith);
  return result;
}

void OT0_free_vertex(OT0_VERTEX o) { delete (World*)o; }

// Bad an API!
int OT0_u8_into_vertex(World *r, void* from, unsigned int off)
{
  return r->deserialize(*(Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>*) from, off);
}


OT0_VERTEX OT0_u8_to_vertex(const void* from, size_t len, unsigned int off)
{
  World *r = new World();
  // let's not ask for efficiency :-/
  r->deserialize(Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>(from, len), off);
  return r;
}

OT0_Buffer OT0_vertex_serialize(const void* w, int k) {
  Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>* b = new Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH>();
  ((World*)w)->serialize(*b, k);
  return b;
}

int OT0_vertex_equal_p(const void* a, const void* b) { return *((World*)a) == *((World*)b); }

int OT0_vertex_type(void* w) { return ((World*)w)->type(); }
uint64_t OT0_vertex_id(void* w) { return ((World*)w)->id(); }
uint64_t OT0_vertex_timestamp(void* w) { return ((World*)w)->timestamp(); }

void OT0_vertex_signature_into(void* into, void* from) {
  C_memcpy(into, &((World*)from)->signature(), ZT_C25519_SIGNATURE_LEN);
}

void OT0_vertex_updatepk_into(void* into, void* from) {
  C_memcpy(into, &((World*)from)->updatesMustBeSignedBy(), ZT_C25519_PUBLIC_KEY_LEN);
}

int OT0_vertex_replacement_p(void* o, void* n) {
  return ((World*)o)->shouldBeReplacedBy(*(World*)n);
}

size_t OT0_vertex_roots(OT0_VERTEX o) { return ((World*)o)->roots().size(); }
OT0_Id OT0_root_id(void* o, size_t i) { return &((World*)o)->roots()[i].identity; }
size_t OT0_root_endpoints(void* o, size_t i) { return ((World*)o)->roots()[i].stableEndpoints.size(); }
const void* OT0_root_endpoint(void* o, size_t i, size_t j) {
  return &((World*)o)->roots()[i].stableEndpoints[j];
}

/* Parameter Controls */

extern unsigned long int OT0_parameter_ping_check_interval; // in Node.cpp

bool OT0_parameter_int_set(OT0_parameter_id key, int64_t val) {
  switch(key) {
  case PING_CHECK:
    if(val<0 || val > ZT_PEER_PING_PERIOD*3) return 0;
    OT0_parameter_ping_check_interval = val;
    break;
  default: return 0;
  }
  return 1;
}
