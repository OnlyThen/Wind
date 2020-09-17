#ifndef SOCKS_H
#define SOCKS_H
#include <stdint.h>
#include <sys/select.h>
#include <sys/types.h>
#include <stdlib.h>

#include "list.h"
#include "encrypt.h"
#include "buffer.h"

#define AE_NONE 0
#define AE_READABLE 1
#define AE_WRITABLE 2
#define AE_NOMORE -1

#define SOCKS_SERVER_CONTEXT 1
#define SOCKS_CONN_CONTEXT 2
#define SOCKS_REMOTE_CONTEXT 3

struct socks_server_context;
typedef void socks_ioproc(void *owner, int fd, void *para, int mask);

enum socks_state {
	OPENING = 0,
	CONNECTING,
	CONNECTED,
};

struct socks_request_frame {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
	uint8_t dst_addr[256];
	uint8_t dst_port[2];
};

struct socks_reply_frame {
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
	uint8_t dst_addr[256];
	uint8_t dst_port[2];
};

struct socks_conn_info {
	char ip[64];
	uint16_t port;
};

struct socks_fd_set {
	fd_set rfds, wfds;
	/* We need to have a copy of the fd sets as it's not safe to reuse
	 * FD sets after select(). */
	fd_set copy_rfds, copy_wfds;
};

struct socks_io_event {
	int mask; /* one of AE_(READABLE|WRITABLE) */
	socks_ioproc *rfproc;
	socks_ioproc *wfproc;
	void *para;
};

struct socks_curr_fd_state {
	int type;
	void *context_ptr;
};

struct socks_remote_context {
    int remote_fd;
	struct socks_server_context *server_entry;
	struct socks_conn_context *conn_entry;
	int fd_mask; /* one of AE_(READABLE|WRITABLE) */
	struct socks_io_event io_proc;
	struct list_head list;
};

struct socks_conn_context {
    int conn_fd;
	struct socks_server_context *server_entry;
	int fd_mask; /* one of AE_(READABLE|WRITABLE) */
	enum socks_state conn_state;
	struct socks_conn_info conn_info;
	struct socks_io_event io_proc;
	struct list_head list;
	int remote_count;
	struct socks_remote_context *remote;
	struct socks_encryptor *encryptor;
};

struct encryptor_key {
	size_t len;
	uint8_t *key;
};

struct socks_server_context {
    int sock_fd;
    int fd_mask;
    uint16_t server_port;
    uint32_t server_addr;
    int conn_count;
    struct socks_conn_context *conn;
	struct socks_remote_context *remote;
	struct socks_io_event io_proc;
	struct buffer *buf;
	int max_fd;
	struct socks_fd_set *ss_allfd_set;
	struct socks_curr_fd_state fd_state[1024 * 10];
	struct socks_encryptor *encryptor;
    ssize_t (*socks_recv)(int sockfd, void *buf, size_t len, int flags, struct socks_conn_context *conn);
	ssize_t (*socks_send)(int sockfd, void *buf, size_t len, int flags, struct socks_conn_context *conn);
};

struct socks_server_context *socks_create_server(uint16_t port, enum socks_encrypt_method encrypt_method, const struct encryptor_key *key);

void socks_release_server(struct socks_server_context *ss_server);

struct socks_conn_context *socks_server_add_conn(struct socks_server_context *s, int conn_fd, int mask, struct socks_conn_info *conn_info);

struct socks_remote_context *socks_conn_add_remote(struct socks_conn_context *conn, int mask, const struct socks_conn_info *remote_info, struct socks_io_event *event);

void socks_server_del_conn(struct socks_server_context *s, struct socks_conn_context *conn);

void socks_del_remote(struct socks_server_context *s, struct socks_remote_context *remote);

int socks_handshake_handle(struct socks_conn_context *conn);

int socks_request_handle(struct socks_conn_context *conn, struct socks_conn_info *remote_info);

void socks_loop(struct socks_server_context *server);

void socks_server_set_handle(struct socks_server_context *server, int mask, socks_ioproc *r_callback, socks_ioproc *w_callback, void *para);

void socks_conn_set_handle(struct socks_conn_context *conn, int mask, socks_ioproc *r_callback, socks_ioproc *w_callback, void *para);

#endif