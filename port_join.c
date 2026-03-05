/**
 * @file port_join.c
 * @brief Implements JOIN_REQUEST/JOIN_RESPONSE handling
 * @note Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <stdlib.h>
#include <string.h>

#include "port.h"
#include "port_private.h"
#include "print.h"
#include "unicast_client.h"
#include "unicast_fsm.h"
#include "util.h"
#include "sad.h"
#include "sad_private.h"

#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define CA_FILE_PATH "ca_cert.pem"

static int load_local_file(const char* filePath, byte* buffer)
{
	FILE* f = fopen(filePath, "rb");
	int length = 0;

	if (f) {
		fseek(f, 0, SEEK_END); // Seek to the end of the file
		length = ftell(f);    // Get the file size (offset from the beginning)
		rewind(f);             // Go back to the start of the file

		// Allocate memory for the entire content plus a null terminator
		buffer = (unsigned char*)malloc(length * sizeof(char));
		if (buffer) {
			// Read the file into the buffer
			fread(buffer, sizeof(char), length, f);
		}
		fclose(f); // Close the file
	}

	return length;
}

/**
 * Generate a random nonce for JOIN_REQUEST
 */
static void generate_nonce(UInteger64 *nonce)
{
	int i, j;

	for (i = 0; i < 16; i++) {
		nonce[i] = 0;
		for (j = 0; j < 8; j++) {
			nonce[i] = (nonce[i] << 8) | (rand() & 0xFF);
		}
	}
}

int port_join(struct port *p)
{
	struct ptp_message *msg;
	int err;

	pr_debug("%s: sending JOIN_REQUEST", p->log_name);

	/* Construct JOIN_REQUEST */
	msg = msg_allocate();
	if (!msg) {
		return -1;
	}

	msg->header.tsmt = JOIN_REQUEST | p->transportSpecific;
	pr_err("[port_join] Header is 0x%08X", msg->header.tsmt);
	msg->header.ver = PTP_VERSION;
	msg->header.messageLength = sizeof(struct join_request_msg);
	msg->header.domainNumber       = clock_domain_number(p->clock);
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId = p->seqnum.join++;
	//msg->header.control = 0x05; /* All others */
	msg->header.logMessageInterval = 0x0;

	/* Generate random nonce */
	generate_nonce(msg->join_request.nonce);
	memcpy(p->nonce, msg->join_request.nonce, sizeof(msg->join_request.nonce));

	err = port_prepare_and_send(p, msg, TRANS_EVENT);
	if (err) {
		pr_err("%s: send JOIN_REQUEST failed", p->log_name);
	}

	return 1;
}

/**
 * Process JOIN_REQUEST message (server side)
 */
int process_join_request(struct port *p, struct ptp_message *m)
{
	struct join_request_msg *req = &m->join_request;
	struct ptp_message *msg;
	int err;
	unsigned char* buffer = NULL;
	int ret = 0;

	/* Validate port state - only process if we are a master */
	switch (p->state) {
	case PS_MASTER:
	case PS_GRAND_MASTER:
		/* Master clocks can respond to JOIN_REQUEST */
		break;
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_PASSIVE:
	case PS_UNCALIBRATED:
	case PS_SLAVE:
	case PS_JOINING:
		/* Non-master states ignore JOIN_REQUEST */
		return 0;
	}

	pr_debug("%s: received JOIN_REQUEST from %s, nonce[0]=0x%lx",
		 p->log_name,
		 pid2str(&m->header.sourcePortIdentity),
		 req->nonce[0]);

	/* Construct JOIN_RESPONSE */
	msg = msg_allocate();
	if (!msg) {
		return -1;
	}

	msg->hwts.type = p->timestamping;
	msg->header.tsmt = JOIN_RESPONSE | p->transportSpecific;
	msg->header.ver = PTP_VERSION;
	msg->header.messageLength = sizeof(struct join_response_msg);
	msg->header.domainNumber = m->header.domainNumber;
	msg->header.sourcePortIdentity = p->portIdentity;
	msg->header.sequenceId = m->header.sequenceId;
	msg->header.control = 0x05; /* All others */
	msg->header.logMessageInterval = 0x0;

	/* Echo back the nonce */
	memcpy(msg->join_response.nonce, req->nonce, sizeof(msg->join_response.nonce));
	int sppId = p->spp;
	struct security_association *sa = sad_get_sa_association(clock_config(p->clock), sppId);
	if (!sa) {
		pr_err("%s: no security association for spp %d", p->log_name, sppId);
		msg_put(msg);
		return -1;
	}

	struct security_association_key *key = sad_get_key_by_id(sa, p->active_key_id);
	if(!key) {
		pr_err("%s: no key id %d for sa %d", p->log_name, p->active_key_id, sppId);
		msg_put(msg);
		return -1;
	}

	msg->join_response.key_id = ntohl(key->key_id);
	msg->join_response.currentSeqNum = 0;
	msg->join_response.spp = ntohl(sppId);
	memset(msg->join_response.cert, 0, sizeof(msg->join_response.cert));
	memset(msg->join_response.sig, 0, sizeof(msg->join_response.sig));
	/* For JOIN_RESPONSE, the key is placed directly after the nonce */

	if(key->data->type == WC_ED25519) {
		unsigned int pubSz = sizeof(msg->join_response.key);
		int ret = wc_ed25519_export_public(key->data->wolfssl.ed25519_key, msg->join_response.key, &pubSz);
		if (ret != 0) {
			pr_err("%s: failed to export ED25519 public key", p->log_name);
			msg_put(msg);
			return -1;
		}
	} else {
		memcpy(msg->join_response.key, key->data->key, key->data->key_len);
	}

	if (strlen(sa->certificate_path) > 0) {
		int length = load_local_file(sa->certificate_path, buffer);
		if (length < 0) {
			pr_err("%s: failed to load certificate from %s", p->log_name, sa->certificate_path);
			msg_put(msg);
			return -1;
		}

		memcpy(msg->join_response.cert, buffer, length);
		msg->join_response.cert_len = length;
		free(buffer);
	}
	
	/* Set destination address */
	msg->address = m->address;

	if (strlen(sa->certificate_key_path) > 0) {
		int length = load_local_file(sa->certificate_key_path, buffer);
		if (length < 0) {
			pr_err("%s: failed to load certificate key from %s", p->log_name, sa->certificate_key_path);
			msg_put(msg);
			return -1;
		}

		/* Sign */
		ret = sign_buffer(
			(const byte*)msg,
			sizeof(struct join_response_msg),
			msg->join_response.sig,
			&msg->join_response.sig_len,
			buffer,
			(word32)length
		);

		if (ret != 0) {
			pr_err("%s: failed to sign JOIN_RESPONSE", p->log_name);
			msg_put(msg);
			return -1;
		}

		free(buffer);
	}

	pr_info("%s: sent JOIN_RESPONSE to %s", p->log_name, pid2str(&m->header.sourcePortIdentity));

	err = port_prepare_and_send(p, msg, TRANS_GENERAL);
	if (err) {
		pr_err("%s: send JOIN_RESPONSE failed", p->log_name);
	} else {
		pr_info("%s: sent JOIN_RESPONSE to %s",
			p->log_name,
			pid2str(&m->header.sourcePortIdentity));
	}

	msg_put(msg);
	return err;
}

/**
 * Process JOIN_RESPONSE message (client side)
 */
int process_join_response(struct port *p, struct ptp_message *m)
{
	struct join_response_msg *resp = &m->join_response;
	char signature[72];
	int signature_len = 0;
	int ret = 0;
	DecodedCert decodedCert;
	DecodedCert decodedCA;
	Signer caSigner;
	unsigned char* caBuffer = NULL;
	ecc_key eccKey;
	unsigned int inOutIdx = 0;

	/* Validate port state - only process if we are a master */
	switch (p->state) {
	case PS_MASTER:
	case PS_GRAND_MASTER:
	case PS_INITIALIZING:
	case PS_FAULTY:
	case PS_DISABLED:
	case PS_LISTENING:
	case PS_PRE_MASTER:
	case PS_PASSIVE:
	case PS_UNCALIBRATED:
	case PS_SLAVE:
	/* Master clocks can respond to JOIN_REQUEST */
		return 0;
	case PS_JOINING:
		/* Non-master states ignore JOIN_REQUEST */
		break;
	}

	if (msg_type(m) != JOIN_RESPONSE) {
		pr_err("%s: received non-JOIN_RESPONSE message", p->log_name);
		return 0;
	}

	if (memcmp(p->nonce, resp->nonce, sizeof(p->nonce)) != 0) {
		pr_warning("%s: nonce is different than expected", p->log_name);
		return 0;
	}

	signature_len = resp->sig_len;
	memcpy(signature, resp->sig, signature_len);
	memset(resp->sig, 0, sizeof(resp->sig));

	int length = load_local_file(CA_FILE_PATH, (byte*)caBuffer);
	if (length < 0) {
		pr_err("%s: failed to load CA certificate", p->log_name);
		return -1;
	}
	InitDecodedCert(&decodedCA, caBuffer, length, 0);
	ret = ParseCert(&decodedCA, CERT_TYPE, NO_VERIFY, NULL);

    caSigner.publicKey  = decodedCA.publicKey;
    caSigner.pubKeySize = decodedCA.pubKeySize;
    caSigner.keyOID     = decodedCA.keyOID;
    XMEMCPY(caSigner.subjectNameHash, decodedCA.subjectHash, KEYID_SIZE);

	InitDecodedCert(&decodedCert, resp->cert, resp->cert_len, 0);
    ret = ParseCert(&decodedCert, CERT_TYPE, VERIFY, &caSigner);
    if (ret != 0) {
        printf("Failed to parse certificate: %d\n", ret);
        return -1;
    }
    ret = wc_ecc_init(&eccKey);
    WOLFSSL_BUFFER(decodedCert.publicKey, decodedCert.pubKeySize);

    ret = wc_EccPublicKeyDecode(decodedCert.publicKey, &inOutIdx, &eccKey, decodedCert.pubKeySize);
    if (ret != 0) {
        printf("Failed to decode ECC public key: %d\n", ret);
        return -1;
    }

	if (verify_buffer((const byte*)resp, sizeof(struct join_response_msg),
                  (const byte*)signature, signature_len,
                  &eccKey) != 0) {
		pr_err("%s: JOIN_RESPONSE signature verification failed", p->log_name);
		return -1;
	}

	int sad_id = htonl(resp->spp);
	int sad = sad_config_init_join(clock_config(p->clock), sad_id);
	if (sad != 0) {
		pr_err("%s: JOIN_RESPONSE security association init failed", p->log_name);
		return -1;
	}

	UInteger32 key_id = htonl(resp->key_id);
	int key = sad_add_key_join(key_id, (unsigned char *)resp->key, sizeof(resp->key));
	if (key != 0) {
		pr_err("%s: JOIN_RESPONSE security key add failed", p->log_name);
		return -1;
	}

	p->spp = sad_id;
	p->active_key_id = key_id;

	ret = sad_readiness_check_join(p->spp, p->active_key_id, clock_config(p->clock));
	if (ret != 0) {
		pr_err("%s: JOIN_RESPONSE security readiness check failed", p->log_name);
		return -1;
	}

	pr_info("Add Key ID: %d", key_id);
	pr_err("%s: JOIN_RESPONSE security readiness check passed", p->log_name);

	port_dispatch(p, EV_JOINED, 0);

	return EV_NONE;
}