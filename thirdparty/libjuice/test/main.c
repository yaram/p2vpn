/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "juice/juice.h"

#include <stdio.h>

int test_crc32(void);
int test_base64(void);
int test_stun(void);
int test_connectivity(void);
int test_notrickle(void);
int test_gathering(void);
int test_turn(void);
int test_conflict(void);
int test_bind(void);

#ifndef NO_SERVER
int test_server(void);
#endif

int main(int argc, char **argv) {
	juice_set_log_level(JUICE_LOG_LEVEL_WARN);

	printf("\nRunning CRC32 implementation test...\n");
	if (test_crc32()) {
		fprintf(stderr, "CRC32 implementation test failed\n");
		return -2;
	}

	printf("\nRunning base64 implementation test...\n");
	if (test_base64()) {
		fprintf(stderr, "base64 implementation test failed\n");
		return -2;
	}

	printf("\nRunning STUN parsing implementation test...\n");
	if (test_stun()) {
		fprintf(stderr, "STUN parsing implementation test failed\n");
		return -3;
	}

	printf("\nRunning STUN/TURN gathering test...\n");
	if (test_gathering()) {
		fprintf(stderr, "STUN/TURN gathering test failed\n");
		return -1;
	}

	printf("\nRunning connectivity test...\n");
	if (test_connectivity()) {
		fprintf(stderr, "Connectivity test failed\n");
		return -1;
	}

	printf("\nRunning TURN connectivity test...\n");
	if (test_turn()) {
		fprintf(stderr, "TURN connectivity test failed\n");
		return -1;
	}

	printf("\nRunning non-trickled connectivity test...\n");
	if (test_notrickle()) {
		fprintf(stderr, "Non-trickled connectivity test failed\n");
		return -1;
	}

	printf("\nRunning connectivity test with role conflict...\n");
	if (test_conflict()) {
		fprintf(stderr, "Connectivity test with role conflict failed\n");
		return -1;
	}

	printf("\nRunning connectivity test with bind address...\n");
	if (test_bind()) {
		fprintf(stderr, "Connectivity test with bind address failed\n");
		return -1;
	}

#ifndef NO_SERVER
	printf("\nRunning server test...\n");
	if (test_server()) {
		fprintf(stderr, "Server test failed\n");
		return -1;
	}
#endif

	return 0;
}

