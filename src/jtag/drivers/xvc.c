/***************************************************************************
 *   Copyright (C) 2021 by Jose Borja Castillo, DTE-UMA                    *
 *   joscassan@uma.es                                                      *
 *                                                                         *
 *   This implementation is XVC protocol 1.0 only, does not support        *
 *   1.1 extension.                                                        *
 *   Some parts of the code are inspired on both bitbang.c and jlink.c     *
 *   by Øyvind Harboe and Paul Fertser, respectively.                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _WIN32
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#else
#include <winsock.h>
#endif
#include "helper/replacements.h"
#include <jtag/interface.h>
#include <jtag/commands.h>
#include "helper/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

static char *xvc_host;
static char *xvc_port;
static uint32_t xvc_tck;

static int xvc_fd;
static uint8_t *xvc_tms_buf;
static uint8_t *xvc_tdi_buf;
static uint8_t *xvc_send_buf;
static uint8_t *xvc_tdo_buf;
/* Being realistic, the protocol won't use as many bits. */
static uint32_t xvc_used_bits;

/* XVC implementation specifics. */
static unsigned int xvc_max_vector_size;
/* max_vector_size discounting command header. */
static unsigned int xvc_max_usable_vector_size;

struct shift_result {
	/* First bit position in TDO to read. */
	unsigned int first;
	/* Number of bits to read. */
	unsigned int length;
	/* Destination address to store the result */
	void *buffer;
	/* Offset in the destination buffer. */
	unsigned int buffer_offset;
};

#define MAX_SHIFT_RESULTS 256
static unsigned int last_used_bits;
static int pending_shift_results;
static struct shift_result shift_result_buffer[MAX_SHIFT_RESULTS];

static int xvc_settck(void);
static int xvc_fill_buffer(void);

/* Auxiliary and TCL helper functions*/
static unsigned int xvc_bits_to_bytes(unsigned int bits)
{
	return (bits + 7) / 8;
}

static int xvc_speed(int speed)
{
	/* Converts TCK speed in kHz to ns. */
	xvc_tck = 1000000 / speed;
	/* Changes default speed to adapter speed */
	return xvc_settck();
}

static int xvc_speed_div(int speed, int *khz)
{
	*khz = speed;

	return ERROR_OK;
}

static int xvc_khz(int khz, int *jtag_speed)
{
	*jtag_speed = khz;

	return ERROR_OK;
}

static int read_frame(int sock_id, unsigned char *ptr, int32_t size)
{
	int32_t i = size;
	while (i > 0) {
		int state = read_socket(sock_id, ptr, i);
		if (state > 0) {
			ptr += state;
			i -= state;
		} else {
			LOG_ERROR("Reading error in read_frame");
			return state;
		}
	}
	return size;
}

static int xvc_flush(void)
{
	if (xvc_used_bits == 0) {
		/* Nothing to send, so we don't expect any bit back either */
		last_used_bits = 0;
		LOG_DEBUG("XVC flush: no bits to flush");
		return ERROR_OK;
	}

	/* Converts bits to bytes, to reckon how many bytes we should send. */
	unsigned int number_of_bytes = xvc_bits_to_bytes(xvc_used_bits);
	/* Creates the header. */
	const char *shift = "shift:";
	int shift_len = strlen(shift);
	int cp_offset = 0;
	/* Copies the header */
	memcpy(xvc_send_buf + cp_offset, shift, shift_len);
	/* Updates the offset. */
	cp_offset += shift_len;
	/* Copies number of bytes. */
	h_u32_to_le(xvc_send_buf + cp_offset, xvc_used_bits);
	cp_offset += sizeof(xvc_used_bits);
	/* Copies TMS vector */
	memcpy(xvc_send_buf + cp_offset, xvc_tms_buf, number_of_bytes);
	cp_offset += number_of_bytes;
	/* Copies TDI vector */
	memcpy(xvc_send_buf + cp_offset, xvc_tdi_buf, number_of_bytes);
	cp_offset += number_of_bytes;
	/* Updates the number of bytes used. */
	LOG_DEBUG("XVC flush: cp_offset: %d", cp_offset);
	LOG_DEBUG("XVC flush: used_bits: %d", xvc_used_bits);

	ssize_t written = write_socket(xvc_fd, xvc_send_buf, cp_offset);
	if (written != cp_offset) {
		LOG_ERROR("Error writing socket in xvc_flush");
		return ERROR_FAIL;
	}

	memset(xvc_tms_buf, 0, xvc_max_usable_vector_size / 2);
	memset(xvc_tdi_buf, 0, xvc_max_usable_vector_size / 2);
	last_used_bits = xvc_used_bits;
	xvc_used_bits = 0;

	return ERROR_OK;
}

static int xvc_queue(const uint8_t *tms, unsigned int tms_offset, const uint8_t *tdi,
		unsigned int tdi_offset, uint8_t *tdo, unsigned int tdo_offset, unsigned int length)
{
	do {
		unsigned int available_length =
				(xvc_max_usable_vector_size / 2) - (xvc_used_bits / 8);
		if ((!available_length) || (pending_shift_results >= MAX_SHIFT_RESULTS)) {
			xvc_flush();
			xvc_fill_buffer();
		}

		struct shift_result *shift_result =
				&shift_result_buffer[pending_shift_results];
		unsigned int scan_length =
				length > available_length ? available_length : length;
		if (tdi)
			buf_set_buf(tdi, tdi_offset, xvc_tdi_buf, xvc_used_bits, scan_length);
		if (tms)
			buf_set_buf(tms, tms_offset, xvc_tms_buf, xvc_used_bits, scan_length);
		if (tdo) {
			shift_result->buffer = tdo;
			shift_result->buffer_offset = tdo_offset;
			shift_result->first = xvc_used_bits;
			shift_result->length = scan_length;
			pending_shift_results++;
		}
		xvc_used_bits += scan_length;
		tdi_offset += scan_length;
		tms_offset += scan_length;
		tdo_offset += scan_length;
		length -= scan_length;
	} while (length > 0);

	return ERROR_OK;
}

static int xvc_getinfo(void)
{
	const char *getinfo = "getinfo:";
	int len = strlen(getinfo);
	/* Sends getinfo command */
	ssize_t written = write_socket(xvc_fd, getinfo, len);
	if (written != len) {
		LOG_ERROR("xvc_getinfo: write");
		return ERROR_FAIL;
	}
	char info_recv_buf[20];
	/* Potentially waits until response gets received. */
	ssize_t read = read_socket(xvc_fd, info_recv_buf, 20);
	if (read < 0) {
		LOG_ERROR("xvc_getinfo: read");
		return ERROR_FAIL;
	}
	LOG_INFO("XVC HW server version: %.19s", info_recv_buf);
	if (strncmp(info_recv_buf, "xvcServer_v1.0:", 15) != 0) {
		/* We got something unexpected. */
		LOG_ERROR("Unexpected response from XVC server");
		return ERROR_FAIL;
	}
	xvc_max_usable_vector_size = strtoul(&info_recv_buf[15], NULL, 10);
	if (xvc_max_usable_vector_size > 32757) {
		LOG_DEBUG("Exceeded maximum vector size, outputting to 32757 bytes");
		xvc_max_usable_vector_size = 32757;
	}
	xvc_max_vector_size = xvc_max_usable_vector_size + 10;
	LOG_DEBUG("Maximum vector size set to: %u\n", xvc_max_vector_size);
	/*Usable size: maximum vector size determined by the server minus the
	sizeof the command, 10 bytes in worst-case (6 bytes from shift: and 4
	additional ones for bit_length).*/
	/* Updates TX Buffer sizes: */
	xvc_send_buf = malloc(xvc_max_vector_size * sizeof(uint8_t));
	xvc_tms_buf = malloc(xvc_max_usable_vector_size / 2 * sizeof(uint8_t));
	xvc_tdi_buf = malloc(xvc_max_usable_vector_size / 2 * sizeof(uint8_t));
	xvc_tdo_buf = malloc(xvc_max_usable_vector_size / 2 * sizeof(uint8_t));
	if (!xvc_send_buf || !xvc_tms_buf || !xvc_tdi_buf || !xvc_tdo_buf) {
		LOG_ERROR("Out of memory");
		free(xvc_send_buf);
		free(xvc_tms_buf);
		free(xvc_tdi_buf);
		free(xvc_tdo_buf);
		return ERROR_FAIL;
	}
	return ERROR_OK;
}

static int xvc_settck(void)
{
	/*Creates the command:
	 * copies the header and appends the value.
	 * */
	uint8_t settck[12];
	const char *header = "settck:";
	memcpy(settck, header, 7);
	h_u32_to_le(settck + 7, xvc_tck);
	/* Writes the request */
	ssize_t written = write_socket(xvc_fd, settck, 11);
	if (written != 11) {
		LOG_ERROR("xvc_settck: write");
		return ERROR_FAIL;
	}
	uint32_t tck_recv_buf;
	/* Potentially waits for a response. */
	ssize_t read = read_socket(xvc_fd, &tck_recv_buf, 4);
	if (read < 0) {
		LOG_ERROR("xvc_settck: read");
		return ERROR_FAIL;
	}
	/* Prints response, regardless of machine endianness. */
	uint32_t xvc_tck_period_ns;
	xvc_tck_period_ns = le_to_h_u32((uint8_t *)&tck_recv_buf);
	LOG_INFO("XVC tck period ns: %u", xvc_tck_period_ns);
	return ERROR_OK;
}

static int xvc_fill_buffer(void)
{
	if (read_frame(xvc_fd, xvc_tdo_buf, (7 + last_used_bits) / 8) < 0) {
		LOG_ERROR("Read_frame");
		return ERROR_FAIL;
	}
	for (int i = 0; i < pending_shift_results; i++) {
		struct shift_result *shift_result = &shift_result_buffer[i];
		buf_set_buf(xvc_tdo_buf, shift_result->first, shift_result->buffer,
				shift_result->buffer_offset, shift_result->length);
	}
	memset(xvc_tdo_buf, 0, xvc_max_usable_vector_size / 2);
	pending_shift_results = 0;
	return ERROR_OK;
}

static int xvc_reset(int trst, int srst)
{
	/*XVC does not have dedicated Reset lines. */
	static bool first_time = true;
	if (first_time) {
		LOG_WARNING("Adapter has no reset lines. Fix \"reset_config\" command in "
				"config file");
		first_time = false;
	}
	return ERROR_OK;
}

static int xvc_init_tcp(void)
{
	struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
	struct addrinfo *result, *rp;
	int fd = 0;

	LOG_INFO("Connecting to %s:%s", xvc_host ? xvc_host : "localhost", xvc_port);

	/* Obtain address(es) matching host/port */
	int s = getaddrinfo(xvc_host, xvc_port, &hints, &result);
	if (s != 0) {
		LOG_ERROR("getaddrinfo: %s\n", gai_strerror(s));
		return ERROR_FAIL;
	}

	/* getaddrinfo() returns a list of address structures.
     Try each address until we successfully connect(2).
     If socket(2) (or connect(2)) fails, we (close the socket
     and) try the next address. */

	for (rp = result; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#ifndef _WIN32
		if (fd == -1)
			continue;
#else
		if (fd == INVALID_SOCKET)
			continue;
#endif

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
			break; /* Success */

		close(fd);
	}

	/* We work hard to collapse the writes into the minimum number, so when
	 * we write something we want to get it to the other end of the
	 * connection as fast as possible. */
	int one = 1;
	/* On Windows optval has to be a const char *. */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));

	freeaddrinfo(result); /* No longer needed */

	if (!rp) { /* No address succeeded */
		LOG_ERROR("Failed to connect");
		return ERROR_FAIL;
	}

	return fd;
}

static int xvc_init_unix(void)
{
	if (!xvc_host) {
		LOG_ERROR("host/socket not specified");
		return ERROR_FAIL;
	}

	LOG_INFO("Connecting to unix socket %s", xvc_host);
	int fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		LOG_ERROR("socket");
		return ERROR_FAIL;
	}

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, xvc_host, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

	if (connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		LOG_ERROR("connect");
		return ERROR_FAIL;
	}

	return fd;
}

/*
 * COMMAND_HANDLERS
 * */
COMMAND_HANDLER(xvc_handle_port_command)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
	uint16_t port;
	COMMAND_PARSE_NUMBER(u16, CMD_ARGV[0], port);
	free(xvc_port);
	xvc_port = (port == 0) ? NULL : strdup(CMD_ARGV[0]);
	return ERROR_OK;
}

COMMAND_HANDLER(xvc_handle_host_command)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;
	free(xvc_host);
	xvc_host = strdup(CMD_ARGV[0]);
	return ERROR_OK;
}

static const struct command_registration xvc_command_handlers[] = {
	{
		.name = "xvc_port",
		.handler = xvc_handle_port_command,
		.mode = COMMAND_CONFIG,
		.help =
				"Set the port to use to connect to the XVC remote server.\n"
				" If 0 or unset, use unix sockets to connect to the remote server.",
		.usage = "port_number",
	},
	{
		.name = "xvc_host",
		.handler = xvc_handle_host_command,
		.mode = COMMAND_CONFIG,
		.help = "Set the host to use to connect to the remote XVC server.\n",
		.usage = "host_name",
	},
	COMMAND_REGISTRATION_DONE
};

static int xvc_init(void)
{
	xvc_used_bits = 0;
	last_used_bits = 0;
	pending_shift_results = 0;
	/* Default clock: 1000 ns period */
	xvc_tck = 1000;

	LOG_INFO("Initializing XVC driver");
	if (!xvc_port)
		xvc_fd = xvc_init_unix();
	else
		xvc_fd = xvc_init_tcp();
	if (xvc_fd < 0)
		return xvc_fd;

	xvc_getinfo();
	xvc_settck();

	LOG_INFO("XVC driver initialized");

	return ERROR_OK;
}

static int xvc_quit(void)
{
	if (close_socket(xvc_fd) != 0) {
		LOG_ERROR("close_socket");
		return ERROR_FAIL;
	}
	free(xvc_port);
	free(xvc_host);
	free(xvc_tms_buf);
	free(xvc_tdi_buf);
	free(xvc_send_buf);
	free(xvc_tdo_buf);
	LOG_INFO("XVC interface quit");
	return ERROR_OK;
}

/* The driver leaves the TCK 0 when in idle */
static void xvc_tap_end_state(tap_state_t state)
{
	assert(tap_is_state_stable(state));
	tap_set_end_state(state);
}

static int xvc_tap_state_move(int skip)
{
	uint8_t tms_scan = tap_get_tms_path(tap_get_state(), tap_get_end_state());
	int tms_count = tap_get_tms_path_len(tap_get_state(), tap_get_end_state());

	xvc_queue(&tms_scan, 0, NULL, 0, NULL, 0, tms_count);

	tap_set_state(tap_get_end_state());
	return ERROR_OK;
}

/*
 * Clock a bunch of TMS (or SWDIO) transitions, to change the JTAG
 * (or SWD) state machine. "Legacy enqueue"
 */
static int xvc_tap_execute_tms(struct jtag_command *cmd)
{
	unsigned int num_bits = cmd->cmd.tms->num_bits;
	const uint8_t *bits = cmd->cmd.tms->bits;

	LOG_DEBUG_IO("TMS: %d bits", num_bits);

	uint8_t tms = 0;

	for (unsigned int i = 0; i < num_bits; i++) {
		tms = ((bits[i / 8] >> (i % 8)) & 1);
		if (xvc_queue(&tms, 0, NULL, 0, NULL, 0, 1) != ERROR_OK)
			return ERROR_FAIL;
	}

	return ERROR_OK;
}

static int xvc_tap_path_move(struct pathmove_command *cmd)
{
	int num_states = cmd->num_states;
	int state_count;
	uint8_t tms = 0xff;

	state_count = 0;
	while (num_states) {
		if (tap_state_transition(tap_get_state(), false) == cmd->path[state_count]) {
			xvc_queue(NULL, 0, NULL, 0, NULL, 0, 1);
		} else if (tap_state_transition(tap_get_state(), true) ==
				cmd->path[state_count]) {
			xvc_queue(&tms, 0, NULL, 0, NULL, 0, 1);
		} else {
			LOG_ERROR("BUG: %s -> %s isn't a valid TAP transition",
					tap_state_name(tap_get_state()),
					tap_state_name(cmd->path[state_count]));
			return ERROR_FAIL;
		}

		tap_set_state(cmd->path[state_count]);
		state_count++;
		num_states--;
	}

	tap_set_end_state(tap_get_state());
	return ERROR_OK;
}

static int xvc_tap_stableclocks(int num_cycles)
{
	uint8_t tms = (tap_get_state() == TAP_RESET ? 0xff : 0);

	for (int i = 0; i < num_cycles; i++)
		xvc_queue(&tms, 0, NULL, 0, NULL, 0, 1);

	return ERROR_OK;
}

static int xvc_tap_runtest(int num_cycles)
{
	tap_state_t saved_end_state = tap_get_end_state();

	/* only do a state_move when we're not already in IDLE */
	if (tap_get_state() != TAP_IDLE) {
		xvc_tap_end_state(TAP_IDLE);
		if (xvc_tap_state_move(0) != ERROR_OK)
			return ERROR_FAIL;
	}

	xvc_tap_stableclocks(num_cycles);

	/* finish in end_state */
	xvc_tap_end_state(saved_end_state);
	if (tap_get_state() != tap_get_end_state())
		if (xvc_tap_state_move(0) != ERROR_OK)
			return ERROR_FAIL;

	return ERROR_OK;
}

static int xvc_tap_scan_write(struct scan_command *cmd)
{
	/* Make sure there are no trailing fields with num_bits == 0, or the logic
	 * below will fail. */
	while (cmd->num_fields > 0 && cmd->fields[cmd->num_fields - 1].num_bits == 0) {
		cmd->num_fields--;
		LOG_DEBUG("discarding trailing empty field");
	}
	if (cmd->num_fields == 0) {
		LOG_DEBUG("empty scan, doing nothing");
		return ERROR_OK;
	}

	bool ir_scan = cmd->ir_scan;
	if (ir_scan) {
		if (tap_get_state() != TAP_IRSHIFT) {
			tap_set_end_state(TAP_IRSHIFT);
			xvc_tap_state_move(0);
		}
	} else {
		if (tap_get_state() != TAP_DRSHIFT) {
			xvc_tap_end_state(TAP_DRSHIFT);
			xvc_tap_state_move(0);
		}
	}
	xvc_tap_end_state(cmd->end_state);

	for (int i = 0; i < cmd->num_fields; i++) {

		/*
		 * Last field
		 * */
		if (i == (cmd->num_fields - 1) && tap_get_state() != tap_get_end_state()) {
			/* All bits except the last one */
			xvc_queue(NULL, 0, cmd->fields[i].out_value, 0, cmd->fields[i].in_value, 0,
					cmd->fields[i].num_bits - 1);
			/* Last bit to copy */
			uint8_t last_bit = 0;
			if (cmd->fields[i].out_value)
				bit_copy(&last_bit, 0, cmd->fields[i].out_value,
						cmd->fields[i].num_bits - 1, 1);
			/* TMS set to 1 to leave the current state. */
			uint8_t tms_bits = 0x01;
			xvc_queue(&tms_bits, 0, &last_bit, 0, cmd->fields[i].in_value,
					cmd->fields[i].num_bits - 1, 1);
			tap_set_state(tap_state_transition(tap_get_state(), 1));
			xvc_queue(&tms_bits, 1, NULL, 0, NULL, 0, 1);
			tap_set_state(tap_state_transition(tap_get_state(), 0));
		} else {
			xvc_queue(NULL, 0, cmd->fields[i].out_value, 0, cmd->fields[i].in_value, 0,
					cmd->fields[i].num_bits);
		}
	}

	if (tap_get_state() != tap_get_end_state()) {
		/* we *KNOW* the above loop transitioned out of
		 * the shift state, so we skip the first state
		 * and move directly to the end state.
		 */

		if (xvc_tap_state_move(0) != ERROR_OK)
			return ERROR_FAIL;
	}
	return ERROR_OK;
}

static int xvc_tap_execute_queue(void)
{
	struct jtag_command *cmd =
			jtag_command_queue; /* currently processed command */

	while (cmd) {
		switch (cmd->type) {
		case JTAG_RUNTEST:
			LOG_DEBUG_IO("runtest %i cycles, end in %s", cmd->cmd.runtest->num_cycles,
					tap_state_name(cmd->cmd.runtest->end_state));
			xvc_tap_end_state(cmd->cmd.runtest->end_state);
			if (xvc_tap_runtest(cmd->cmd.runtest->num_cycles) != ERROR_OK)
				return ERROR_FAIL;
			break;
		case JTAG_STABLECLOCKS:
			/* this is only allowed while in a stable state.  A check for a stable
			 * state was done in jtag_add_clocks()
			 */
			if (xvc_tap_stableclocks(cmd->cmd.stableclocks->num_cycles) != ERROR_OK)
				return ERROR_FAIL;
			break;
		case JTAG_TLR_RESET:
			LOG_DEBUG_IO("statemove end in %s",
					tap_state_name(cmd->cmd.statemove->end_state));
			xvc_tap_end_state(cmd->cmd.statemove->end_state);
			if (xvc_tap_state_move(0) != ERROR_OK)
				return ERROR_FAIL;
			break;
		case JTAG_PATHMOVE:
			LOG_DEBUG_IO(
					"pathmove: %i states, end in %s", cmd->cmd.pathmove->num_states,
					tap_state_name(
							cmd->cmd.pathmove->path[cmd->cmd.pathmove->num_states - 1]));
			if (xvc_tap_path_move(cmd->cmd.pathmove) != ERROR_OK)
				return ERROR_FAIL;
			break;
		case JTAG_SCAN:
			if (xvc_tap_scan_write(cmd->cmd.scan) != ERROR_OK)
				return ERROR_FAIL;
			break;
		case JTAG_SLEEP:
			LOG_DEBUG_IO("sleep %" PRIi32, cmd->cmd.sleep->us);
			jtag_sleep(cmd->cmd.sleep->us);
			break;
		case JTAG_TMS:
			if (xvc_tap_execute_tms(cmd) != ERROR_OK)
				return ERROR_FAIL;
			break;
		default:
			LOG_ERROR("BUG: unknown JTAG command type encountered");
			return ERROR_FAIL;
		}
		cmd = cmd->next;
	}

	if (xvc_flush() != ERROR_OK)
		return ERROR_FAIL;
	if (xvc_fill_buffer() != ERROR_OK)
		return ERROR_FAIL;
	/* return ERROR_OK, unless a previous ERROR has been
	 * returned.
	 */
	return ERROR_OK;
}

static struct jtag_interface xvc_interface = {
	.execute_queue = &xvc_tap_execute_queue,
	.supported = DEBUG_CAP_TMS_SEQ,
};

struct adapter_driver xvc_driver = {
	.name = "xvc",
	.transports = jtag_only,
	.commands = xvc_command_handlers,
	.init = xvc_init,
	.quit = xvc_quit,
	.reset = &xvc_reset,
	.speed = &xvc_speed,
	.khz = &xvc_khz,
	.speed_div = &xvc_speed_div,
	.jtag_ops = &xvc_interface,
};
