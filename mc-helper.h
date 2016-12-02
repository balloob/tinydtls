#ifndef _DTLS_MC_HELPER_H
#define _DTLS_MC_HELPER_H

int joinmc(char* group, struct sockaddr_in6 *dst, int fd);

int fake_key_block(session_t *dst, dtls_context_t *ctx, dtls_peer_type role, unsigned char *psk, uint8_t groupid);

/* some constants for the PRF */
#define PRF_LABEL(Label) prf_label_##Label
#define PRF_LABEL_SIZE(Label) (sizeof(PRF_LABEL(Label)) - 1)
static const unsigned char prf_label_master[] = "master secret";
static const unsigned char prf_label_key[] = "key expansion";
static const unsigned char prf_label_client[] = "client";
static const unsigned char prf_label_server[] = "server";
static const unsigned char prf_label_finished[] = " finished";

#endif
