#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>
#include <getopt.h>

#include "alert.h"
#include "crypto.h"
#include "dtls.h"
#include "dtls_config.h"
#include "dtls_debug.h"
#include "peer.h"

#include "mc-helper.h"

#ifdef __APPLE__
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP    IPV6_LEAVE_GROUP
#endif

#ifndef __USE_XOPEN2K
#warning "no XOPEN2K"
#endif

#ifndef __USE_GNU
#warning "no GNU"
#endif

static int
resolve_address(const char *server, struct sockaddr *dst) {
  
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;

  memset(addrstr, 0, sizeof(addrstr));
  if (server && strlen(server) > 0)
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
    case AF_INET6:

      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
      return ainfo->ai_addrlen;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return -1;
}

/** send IPV6_ADD_MEMBERSHIP with mc-address given in \p dst */
int 
joinmc(char* group, struct sockaddr_in6 *dst, int fd)
{
  resolve_address(group, (struct sockaddr*)dst);

  struct ipv6_mreq mreq;
  
  memcpy(&mreq.ipv6mr_multiaddr, &(dst->sin6_addr), sizeof(dst->sin6_addr));
  mreq.ipv6mr_interface = 0;
  
  if(setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq))){
    dtls_alert("setsockopt IPV6_ADD_MEMBERSHIP: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

/* copy pasta from dtls.c */
/** Dump out the cipher keys and IVs used for the symetric cipher. */
static void 
dtls_debug_keyblock(dtls_security_parameters_t *config)
{
  dtls_debug("key_block (%d bytes):\n", dtls_kb_size(config, peer->role));
  dtls_debug_dump("  client_MAC_secret",
		  dtls_kb_client_mac_secret(config, peer->role),
		  dtls_kb_mac_secret_size(config, peer->role));

  dtls_debug_dump("  server_MAC_secret",
		  dtls_kb_server_mac_secret(config, peer->role),
		  dtls_kb_mac_secret_size(config, peer->role));

  dtls_debug_dump("  client_write_key",
		  dtls_kb_client_write_key(config, peer->role),
		  dtls_kb_key_size(config, peer->role));

  dtls_debug_dump("  server_write_key",
		  dtls_kb_server_write_key(config, peer->role),
		  dtls_kb_key_size(config, peer->role));

  dtls_debug_dump("  client_IV",
		  dtls_kb_client_iv(config, peer->role),
		  dtls_kb_iv_size(config, peer->role));

  dtls_debug_dump("  server_IV",
		  dtls_kb_server_iv(config, peer->role),
		  dtls_kb_iv_size(config, peer->role));
}

dtls_handshake_parameters_t 
make_handshake(char* client_random, int client_random_length, char* server_random, int server_random_length)
{
  dtls_handshake_parameters_t handshake;
  handshake.cipher = TLS_PSK_WITH_AES_128_CCM_8;
  memset(handshake.tmp.random.client, 0, DTLS_RANDOM_LENGTH); //TODO: do we need these outside the handshake?
  memset(handshake.tmp.random.server, 0, DTLS_RANDOM_LENGTH);
  
  client_random_length = (client_random_length > DTLS_RANDOM_LENGTH) ? DTLS_RANDOM_LENGTH : client_random_length;
  memcpy(handshake.tmp.random.client, client_random, client_random_length);
  server_random_length = (server_random_length > DTLS_RANDOM_LENGTH) ? DTLS_RANDOM_LENGTH : server_random_length;
  memcpy(handshake.tmp.random.server, server_random, server_random_length);

  return handshake;
}

static dtls_peer_t *
make_peer(session_t *dst, dtls_peer_type role, dtls_context_t *ctx){ //TODO: make peer inline?
  dtls_peer_t *peer = dtls_new_peer(dst);
  peer->role = role;
  peer->state = DTLS_STATE_CONNECTED;
  
  if (dtls_add_peer(ctx, peer) < 0) {
    dtls_alert("cannot add peer\n");
    return 0;
  }
  
  return peer;
}

int
fake_key_block(
  session_t *dst,
  dtls_context_t *ctx,
  dtls_peer_type role,
  unsigned char *psk,
  uint8_t groupid)
{
  unsigned char *pre_master_secret;
  int pre_master_len = 0;
  dtls_handshake_parameters_t handshake = make_handshake(0,0,0,0);
  dtls_peer_t *peer = make_peer(dst, role, ctx);
  
  dtls_security_parameters_t *security = dtls_security_params_next(peer);
  uint8 master_secret[DTLS_MASTER_SECRET_LENGTH];

  if (!security) {
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  pre_master_secret = security->key_block;

  switch (handshake.cipher) {
#ifdef DTLS_PSK
  case TLS_PSK_WITH_AES_128_CCM_8: {
    int len;
    if(psk)
    {
      len = strlen((char *)psk);
    } else {
      return -1;
    }
    
    /* Temporarily use the key_block storage space for the pre master secret. */
    pre_master_len = dtls_psk_pre_master_secret(psk, len, pre_master_secret, MAX_KEYBLOCK_LENGTH);

    dtls_debug_hexdump("psk", psk, len);

    memset(psk, 0, DTLS_PSK_MAX_KEY_LEN);
    if (pre_master_len < 0) {
      dtls_crit("the psk was too long, for the pre master secret\n");
      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
    }

    break;
  }
#endif /* DTLS_PSK */
  default:
    dtls_crit("calculate_key_block: unknown cipher\n");
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
  }

  dtls_debug_dump("client_random", handshake.tmp.random.client, DTLS_RANDOM_LENGTH);
  dtls_debug_dump("server_random", handshake.tmp.random.server, DTLS_RANDOM_LENGTH);
  dtls_debug_dump("pre_master_secret", pre_master_secret, pre_master_len);

  /* Hash Magic */
  dtls_prf(pre_master_secret, pre_master_len,
	   PRF_LABEL(master), PRF_LABEL_SIZE(master),
	   handshake.tmp.random.client, DTLS_RANDOM_LENGTH,
	   handshake.tmp.random.server, DTLS_RANDOM_LENGTH,
	   master_secret,
	   DTLS_MASTER_SECRET_LENGTH);

  dtls_debug_dump("master_secret", master_secret, DTLS_MASTER_SECRET_LENGTH);

  /* create key_block from master_secret
   * key_block = PRF(master_secret,
                    "key expansion" + tmp.random.server + tmp.random.client) */

  /* more Magic */
  dtls_prf(master_secret,
	   DTLS_MASTER_SECRET_LENGTH,
	   PRF_LABEL(key), PRF_LABEL_SIZE(key),
	   handshake.tmp.random.server, DTLS_RANDOM_LENGTH,
	   handshake.tmp.random.client, DTLS_RANDOM_LENGTH,
	   security->key_block, //<- yay keys
	   dtls_kb_size(security, role));

  memcpy(handshake.tmp.master_secret, master_secret, DTLS_MASTER_SECRET_LENGTH); //< why do we need this?
  dtls_debug_keyblock(security);

  security->cipher = handshake.cipher;
  security->compression = handshake.compression;
  security->rseq = 0;
  if(role == DTLS_CLIENT)
  {
    security->rseqgroup = groupid;
  }
  
  /* and switch cipher suite */
  dtls_security_params_switch(peer);

  return 0;
}
