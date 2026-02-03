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
	/* For JOIN_RESPONSE, the key is placed directly after the nonce */
	memcpy(msg->join_response.key, key->data->key, key->data->key_len); // Ed25519

	/* Set destination address */
	msg->address = m->address;

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

	int sad = sad_config_init_join(clock_config(p->clock), 100);
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

	p->spp = 100;
	p->active_key_id = key_id;

	int ret = sad_readiness_check_join(p->spp, p->active_key_id, clock_config(p->clock));
	if (ret != 0) {
		pr_err("%s: JOIN_RESPONSE security readiness check failed", p->log_name);
		return -1;
	}

	pr_info("Add Key ID: %d", key_id);
	print_hex_array((unsigned char *)resp->key, 32);
	pr_err("%s: JOIN_RESPONSE security readiness check passed", p->log_name);

	p->state = PS_UNCALIBRATED;
	port_dispatch(p, EV_RS_SLAVE, 1);

	return EV_NONE;
}