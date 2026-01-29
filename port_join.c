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
	msg->header.logMessageInterval = 0x7f;

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
		 m->join_request.nonce[0]);

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
	msg->header.logMessageInterval = 0x7f;
	msg->header.flagField[0] = UNICAST;

	/* Echo back the nonce */
	memcpy(msg->join_response.nonce, m->join_request.nonce, sizeof(msg->join_response.nonce));

	/* Set destination address */
	msg->address = m->address;

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
	if (p->state == PS_JOINING && msg_type(m) == JOIN_RESPONSE) {
		return EV_JOINED;
	}
	return EV_NONE;
}