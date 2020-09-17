#include <stdio.h>
#include "socks.h"
#include "socket_wrap.h"
#include "debug.h"

static char *remote_ip = "127.0.0.1";
static uint16_t remote_port = 1984;
static uint16_t listen_port = 2080;

static void socks_remote_io_handle(void *remote, int fd, void *data, int mask) {
	int readed;
	int ret;
	struct socks_remote_context *remote_ptr = remote;
	struct socks_conn_context *conn = remote_ptr->conn_entry;
	struct socks_server_context *server = remote_ptr->server_entry;
	struct buffer *buf = server->buf;

	if (conn == NULL) {
		socks_del_remote(server, remote_ptr);
		return;
	}
	readed = server->socks_recv(fd, buf->data, buf->max, MSG_DONTWAIT, conn);
	if (readed <= 0) {
		socks_del_remote(server, remote_ptr);
		return;
	}
	ret = send(conn->conn_fd, buf->data, readed, 0);
	if (ret != readed) {
		debug_print("send return %d, should send %d: %s", ret, readed, strerror(errno));
		if (ret == -1 && errno != EAGAIN) {
			socks_del_remote(remote_ptr->server_entry, remote_ptr);
        }
	}
}

static void client_to_remote(struct socks_conn_context *conn) {
	int readed;
	int ret;
	struct socks_server_context *server = conn->server_entry;
	struct buffer *buf = server->buf;
	struct socks_remote_context *remote;

	if (conn->remote == NULL) {
		socks_server_del_conn(server, conn);
		return;
	}
	readed = recv(conn->conn_fd, buf->data, buf->max, MSG_DONTWAIT);
	if (readed <= 0) {
		socks_server_del_conn(server, conn);
		return;
	}
	remote = conn->remote;
	ret = server->socks_send(remote->remote_fd, buf->data, readed, 0, conn);
	if (ret != readed) {
		debug_print("send return %d, should send %d: %s", ret, readed, strerror(errno));
		if (ret == -1 && errno != EAGAIN) {
			socks_server_del_conn(server, conn);
        }
	}
}

static void socks_io_handle(void *conn, int fd, void *data, int mask) {
	struct socks_conn_context *conn_ptr = conn;
	struct socks_conn_info remote_info;
	struct socks_io_event event = {
		.mask = AE_READABLE,
		.rfproc = socks_remote_io_handle, /* server 可读 */
		.wfproc = NULL,
		.para = NULL,
	};

	strncpy(remote_info.ip, remote_ip, sizeof(remote_info.ip));
	remote_info.port = remote_port;
	switch (conn_ptr->conn_state) {
	case OPENING:
		if (socks_handshake_handle(conn_ptr) < 0) {
			return;
        }
		if (socks_conn_add_remote(conn_ptr, AE_READABLE, &remote_info, &event) == NULL) {
			debug_print("ss_conn_add_remote() failed: %s", strerror(errno));
			goto err;
		}
		conn_ptr->conn_state = CONNECTING;
		break;
	case CONNECTING:
	case CONNECTED:
		/* TODO */
		client_to_remote(conn_ptr);
		break;
	default:
		debug_print("unknow state: %d", conn_ptr->conn_state);
	}
	return;
err:
	debug_print("close");
	socks_server_del_conn(conn_ptr->server_entry, conn_ptr);
}

static void socks_accept_handle(void *s, int fd, void *data, int mask) {
	int conn_fd;
	struct socks_conn_info conn_info;
	struct socks_conn_context *conn_ctx;

	conn_fd = socks_accept(fd, conn_info.ip, &conn_info.port);
	if (conn_fd < 0) {
		debug_print("ss_accetp failed: %s", strerror(errno));
		return;
	}
	conn_ctx = socks_server_add_conn(s, conn_fd, AE_READABLE, &conn_info);
	if (conn_ctx == NULL) {
		debug_print("ss_server_add_conn failed: %s", strerror(errno));
		return;
	}
	socks_conn_set_handle(conn_ctx, AE_READABLE, socks_io_handle, NULL, NULL);
}

int main(int argc, char *argv[])
{
	struct socks_server_context *local_server;
	enum socks_encrypt_method encry_method = NO_ENCRYPT;
	struct encryptor_key *enc_key = NULL;
	size_t key_len;
	int opt;
	if (argc == 1) {
		fprintf(stderr, "usage: %s [-l remote_ip] [-p remote_port] [-s listen_port] [-m xor|rc4] [-e key]\n", argv[0]);
		exit(1);
	}
	while ((opt = getopt(argc, argv, "l:p:s:m:e:h?")) != -1) {
		switch (opt) {
		case 'l':
			remote_ip = optarg;
			break;
		case 'p':
			remote_port = atoi(optarg);
			break;
		case 's':
			listen_port = atoi(optarg);
			break;
		case 'm':
			if (!strcmp("xor", optarg))
				encry_method = XOR_METHOD;
			else if (!strcmp("rc4", optarg))
				encry_method = RC4_METHOD;
			break;
		case 'e':
			key_len = strlen(optarg);
			enc_key = malloc(sizeof(*enc_key));
			enc_key->len = key_len;
			enc_key->key = malloc(key_len);
			memcpy(enc_key->key, optarg, key_len);
			break;
		default:
			fprintf(stderr, "usage: %s [-l remote_ip] [-p remote_port] [-s listen_port] [-m xor|rc4] [-e key]\n", argv[0]);
			exit(1);
		}
	}
	
	local_server = socks_create_server(listen_port, encry_method, enc_key);
	if (local_server == NULL) {
		DIE("ss_create_server failed!");
    }
	socks_server_set_handle(local_server, AE_READABLE, socks_accept_handle, NULL, NULL);
	socks_loop(local_server);
	socks_release_server(local_server);
	return 0;
}