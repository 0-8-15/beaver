#ifndef OT0_HOOKS_DEFINED
#define OT0_HOOKS_DEFINED 1

#ifdef __cplusplus
extern "C" {
#if 0
} // keep emacs indent happy
#endif
#else
#ifndef OT0_BOOL_DEFINED
#define OT0_BOOL_DEFINED 1
typedef enum{ false=0, true=1} bool;
#endif
#endif


#include <stdlib.h>
#include <stdint.h>
#define C_memcpy memcpy

uint64_t OT0_now();

size_t OT0_C25519_PUBLIC_KEY_SIZE();
size_t OT0_C25519_PRIVATE_KEY_SIZE();
size_t OT0_C25519_SIGNATURE_SIZE();
size_t OT0_C25519_KEYPAIR_SIZE();
size_t OT0_SOCKADDR_STORAGE_SIZE();

void OT0_C25519_gen_kp(void*);
void OT0_C25519_key_agree(void* sk, void* pk, void* key, size_t size);
void OT0_C25519_sign2(const void* sk, const void* pk, const void* buffer, size_t size, void* result);
bool OT0_C25519_verify(const void* pk, const void* buffer, size_t size, const void* signature);

void OT0_sockaddr_into_string(const void* sa, char buf[64]);
void* OT0_sockaddr_from_string(const char* str);
void OT0_free_sockaddr(void* addr);
  
typedef const void* OT0_Id;
OT0_Id OT0_generate_Id();
OT0_Id OT0_new_Id_from_string(const char*str);
void OT0_g_free_ID(OT0_Id);
void OT0_Id_to_string(OT0_Id, bool, char*);
const void* OT0_ID_pk(OT0_Id id);
void OT0_ID_kp_into(OT0_Id id, void* result);

typedef void* OT0_Buffer;

OT0_Buffer OT0__make_vertex_buffer();
void OT0__free_vertex_buffer(OT0_Buffer);
size_t OT0_Buffer_length(void* b);
void* OT0_Buffer_data(void* b);

typedef void* OT0_VERTEX;

typedef void* OT0_ROOTS;

OT0_ROOTS OT0_make_roots();
void OT0_free_roots(OT0_ROOTS);
size_t OT0_roots_length(OT0_ROOTS roots);
size_t OT0_add_root(OT0_ROOTS, OT0_Id);
size_t OT0_add_root_endpoint(OT0_ROOTS, size_t, const void*);

OT0_VERTEX OT0_make_vertex(uint64_t id, unsigned int type, void* roots, uint64_t ts,
                           void* update_pk, void* sign_pk, void* sign_sk);
void OT0_free_vertex(OT0_VERTEX o);


OT0_VERTEX OT0_u8_to_vertex(const void* from, size_t len, unsigned int off);
OT0_Buffer OT0_vertex_serialize(const void* w, int k);
int OT0_vertex_equal_p(const void* a, const void* b);

int OT0_vertex_type(void* w);
uint64_t OT0_vertex_id(void* w);
uint64_t OT0_vertex_timestamp(void* w);
void OT0_vertex_signature_into(void* into, void* from);
void OT0_vertex_updatepk_into(void* into, void* from);
int OT0_vertex_replacement_p(void* o, void* n);

size_t OT0_vertex_roots(OT0_VERTEX);
OT0_Id OT0_root_id(void* o, size_t i);
size_t OT0_root_endpoints(void* o, size_t i);
const void* OT0_root_endpoint(void* o, size_t i, size_t j);

#ifdef __cplusplus
}
#endif
#endif
