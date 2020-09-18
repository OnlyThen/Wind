#include "socks.h"
#include "encrypt.h"
#include "socket_wrap.h"
#include "debug.h"
#include <strings.h>
#include <sys/socket.h>

static int socks_fd_set_init(struct socks_fd_set **fd_set) {
	*fd_set = malloc(sizeof(struct socks_fd_set));

	if (*fd_set == NULL) {
		return -1;
	}
	FD_ZERO(&(*fd_set)->rfds);
	FD_ZERO(&(*fd_set)->wfds);
	return 0;
}

static int socks_fd_set_add_fd(struct socks_fd_set *fd_set, int fd, int mask) {
	if (mask & AE_READABLE) {
		FD_SET(fd, &fd_set->rfds);
	}
	if (mask & AE_WRITABLE) {
		FD_SET(fd, &fd_set->wfds);
	}
	return 0;
}

static void socks_fd_set_del_fd(struct socks_fd_set *fd_set, int fd, int mask) {
	if (mask & AE_READABLE)
		FD_CLR(fd, &fd_set->rfds);
	if (mask & AE_WRITABLE)
		FD_CLR(fd, &fd_set->wfds);
}

static ssize_t _recv(int sockfd, void *buf, size_t len, int flags, struct socks_conn_context *conn) {
	return recv(sockfd, buf, len, flags);
}

static ssize_t decry_recv(int sockfd, void *buf, size_t len, int flags, struct socks_conn_context *conn) {
	ssize_t ret;

	ret = recv(sockfd, buf, len, flags);
	if (ret > 0) {
		socks_decrypt(conn->encryptor, buf, buf, ret);
	}
	return ret;
}

static ssize_t _send(int sockfd, void *buf, size_t len, int flags, struct socks_conn_context *conn) {
	return send(sockfd, buf, len, flags);
}

static ssize_t encry_send(int sockfd, void *buf, size_t len, int flags, struct socks_conn_context *conn) {
	socks_decrypt(conn->encryptor, buf, buf, len);
	return send(sockfd, buf, len, flags);
}

static struct socks_request_frame *socks_get_requests(struct socks_request_frame *request, int fd, struct socks_conn_context *conn) {
	struct socks_server_context *server = conn->server_entry;
	struct buffer *buf = server->buf;
	ssize_t ret;

	ret = server->socks_recv(fd, buf->data, 4, 0, conn);
	if (ret != 4) {
		return NULL;
	}
	if (buf->data[0] != 0x05 || buf->data[2] != 0) {
		return NULL;
	}
	if (buf->data[1] != 0x01) {
 		debug_print("only support CONNECT CMD now -_-");
 		return NULL;
 	}
	request->ver = 0x05;
	request->cmd = buf->data[1];
	request->rsv = 0x0;
	switch (buf->data[3]) { /* ATYP */
	case 0x01: /* IPv4 */
		request->atyp = 0x01;
		ret = server->socks_recv(conn->conn_fd, request->dst_addr, 4, 0, conn);
		if (ret != 4) {
			return NULL;
		}
		request->dst_addr[ret] = '\0';
		break;
	case 0x03: /* Domain name */
		request->atyp = 0x03;
		ret = server->socks_recv(conn->conn_fd, request->dst_addr, 1, 0, conn);
		if (ret != 1) {
			return NULL;
		}
		if (ret > 255) {
			return NULL;
		}
		ret = server->socks_recv(conn->conn_fd, &request->dst_addr[1], request->dst_addr[0], 0, conn);
		if (ret != request->dst_addr[0]) {
			return NULL;
		}
		request->dst_addr[ret + 1] = '\0';
		break;
	case 0x04: /* IPv6 */
		request->atyp = 0x04;
		ret = server->socks_recv(conn->conn_fd, request->dst_addr, 16, 0, conn);
		if (ret != 16) {
			return NULL;
		}
		break;
	default:
		debug_print("err ATYP: %x", buf->data[3]);
		return NULL;
	}
	ret = server->socks_recv(conn->conn_fd, request->dst_port, 2, 0, conn);
	if (ret != 2) {
		return NULL;
	}
	return request;
}

static struct socks_conn_info *get_addr_info(const struct socks_request_frame *request, struct socks_conn_info *remote_info) {
	struct in_addr remote_addr;
	struct hostent *hptr;
	char **pptr;
	char str[INET_ADDRSTRLEN] = {0,};
	char *addr_tmp;

	bzero(&remote_addr, sizeof(remote_addr));
	switch (request->atyp) {
	case 0x01: /* ip v4 */
		memcpy(&remote_addr.s_addr, request->dst_addr, sizeof(remote_addr.s_addr));
		sprintf(remote_info->ip, "%s", inet_ntoa(remote_addr));
		break;
	case 0x03: /* domainname */
		addr_tmp = alloca(request->dst_addr[0] + 1);
		memcpy(addr_tmp, (char *)&request->dst_addr[1], request->dst_addr[0]);
		addr_tmp[request->dst_addr[0]] = '\0';
		if ((hptr = gethostbyname(addr_tmp)) == NULL) {
			debug_print("gethostbyname() %s failed: %s", &request->dst_addr[1], strerror(errno));
			return NULL;
		}
		if (hptr->h_addrtype == AF_INET) {
			pptr = hptr->h_addr_list;
			for (; *pptr != NULL; pptr++) {
				sprintf(remote_info->ip, "%s", inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
			}
		}
		break;
	case 0x04: /* ip v6 */
		//TODO
		break;
	default:
		debug_print("unknow atyp: %d", request->atyp);
		return NULL;
	}
	remote_info->port = ntohs(*((uint16_t *)(request->dst_port)));
	return remote_info;
}

static int socks_poll(struct socks_server_context *server) {
	int events_num = 0;
	int retval;
	struct socks_fd_set *set = server->ss_allfd_set;
	struct socks_conn_context *conn;
	struct socks_remote_context *remote;

	memcpy(&set->copy_rfds, &set->rfds, sizeof(fd_set));
	memcpy(&set->copy_wfds, &set->wfds, sizeof(fd_set));
	retval = select(server->max_fd + 1, &set->copy_rfds, &set->copy_wfds, NULL, NULL);
	//printf("retval: %d\n", retval);
	if (retval > 0) {
		if (FD_ISSET(server->sock_fd, &set->copy_rfds)) {
			server->io_proc.mask |= AE_READABLE;
			server->fd_state[events_num].type = SOCKS_SERVER_CONTEXT;
			server->fd_state[events_num].context_ptr = server;
			events_num += 1;
		}
		list_for_each_entry(conn, &server->conn->list, list) {
			if (conn->fd_mask & AE_READABLE && FD_ISSET(conn->conn_fd, &set->copy_rfds)) {
				conn->io_proc.mask |= AE_READABLE;
				server->fd_state[events_num].type = SOCKS_CONN_CONTEXT;
				server->fd_state[events_num].context_ptr = conn;
				events_num += 1;
			}
		}
		list_for_each_entry(remote, &server->remote->list, list) {
			if (remote->fd_mask & AE_READABLE && FD_ISSET(remote->remote_fd, &set->copy_rfds)) {
				remote->io_proc.mask |= AE_READABLE;
				server->fd_state[events_num].type = SOCKS_REMOTE_CONTEXT;
				server->fd_state[events_num].context_ptr = remote;
				events_num += 1;
			}
		}
	}
	return events_num;
}

struct socks_server_context *socks_create_server(uint16_t port, enum socks_encrypt_method encrypt_method, const struct encryptor_key *key) {
	struct socks_server_context *server = calloc(1, sizeof(struct socks_server_context));
	if (server == NULL) {
		return NULL;
	}
	server->buf = buf_create(4096);
	if (server->buf == NULL){
		return NULL;
	}
	server->sock_fd = create_server_socket(port);
	if (server->sock_fd < 0) {
		DIE("create_server_socket failed");
	}
	server->fd_mask = AE_READABLE;
	server->max_fd = server->sock_fd;
	if (socks_fd_set_init(&server->ss_allfd_set) < 0) {
		DIE("socks_fd_set_init failed");
	}
	if (socks_fd_set_add_fd(server->ss_allfd_set, server->sock_fd, AE_READABLE) < 0) {
		DIE("socks_fd_set_add_fd failed");
	}
	server->conn = calloc(1, sizeof(*server->conn));
	if (server->conn == NULL) {
		DIE("calloc failed");
	}
	INIT_LIST_HEAD(&server->conn->list);
	server->remote = calloc(1, sizeof(*server->remote));
	if (server->remote == NULL) {
		DIE("calloc failed");
	}
	INIT_LIST_HEAD(&server->remote->list);
	if (key) {
		server->encryptor = socks_create_encryptor(encrypt_method, key->key, key->len);
		server->socks_recv = decry_recv;
		server->socks_send = encry_send;
	} else {
		server->socks_recv = _recv;
		server->socks_send = _send;
	}
	return server;
}
//Check
void socks_release_server(struct socks_server_context *ss_server) {
	socks_release_encryptor(ss_server->encryptor);
	free(ss_server->ss_allfd_set);
	buf_release(ss_server->buf);
	free(ss_server);
}

struct socks_conn_context *socks_server_add_conn(struct socks_server_context *s, int conn_fd, int mask, struct socks_conn_info *conn_info) {
	struct socks_conn_context *new_conn;

	new_conn = calloc(1, sizeof(*new_conn));
	if (new_conn == NULL) {
		debug_print("colloc failed: %s", strerror(errno));
		return NULL;
	}
	new_conn->conn_fd = conn_fd;
	new_conn->server_entry = s;
	new_conn->fd_mask = mask;
	new_conn->conn_state = OPENING;
	if (conn_info) {
		strncpy(new_conn->conn_info.ip, conn_info->ip, sizeof(new_conn->conn_info.ip) - 1);
		new_conn->conn_info.ip[sizeof(new_conn->conn_info.ip) - 1] = '\0';
		new_conn->conn_info.port = conn_info->port;
	}
	list_add(&new_conn->list, &s->conn->list);
	s->conn_count += 1;
	s->max_fd = (conn_fd > s->max_fd) ? conn_fd : s->max_fd;
	if (socks_fd_set_add_fd(s->ss_allfd_set, conn_fd, mask) < 0) {
		DIE("socks_fd_set_add_fd failed");
	}
	if (s->encryptor) {
		new_conn->encryptor = malloc(sizeof(*new_conn->encryptor));
		memcpy(new_conn->encryptor, s->encryptor, sizeof(*s->encryptor));
	}
	return new_conn;
}

struct socks_remote_context *socks_conn_add_remote(struct socks_conn_context *conn, int mask, const struct socks_conn_info *remote_info, struct socks_io_event *event) {
	struct socks_remote_context *new_remote;
	struct socks_server_context *s = conn->server_entry;

	new_remote = calloc(1, sizeof(struct socks_remote_context));
	if (new_remote == NULL) {
		debug_print("calloc failed: %s", strerror(errno));
		return NULL;
	}
	new_remote->remote_fd = client_connect(remote_info->ip, remote_info->port);
	if (new_remote->remote_fd < 0) {
		debug_print("client_connect() failed: %s", strerror(errno));
		return NULL;
	}
	new_remote->server_entry = s;
	new_remote->conn_entry = conn;
	new_remote->fd_mask = mask;
	if (event) {
		memcpy(&new_remote->io_proc, event, sizeof(*event));
	}
	conn->remote = new_remote;
	conn->remote_count += 1;
	s->max_fd = (new_remote->remote_fd > s->max_fd) ? new_remote->remote_fd : s->max_fd;
	if (socks_fd_set_add_fd(s->ss_allfd_set, new_remote->remote_fd, mask) < 0) {
		DIE("socks_fd_set_add_fd failed");
	}
	list_add(&new_remote->list, &s->remote->list) ;
	return new_remote;
}

void socks_server_del_conn(struct socks_server_context *s, struct socks_conn_context *conn) {
	struct socks_remote_context *remote = conn->remote;
	if (conn->remote != NULL) {
		remote->conn_entry = NULL;
	}
	socks_fd_set_del_fd(s->ss_allfd_set, conn->conn_fd, conn->fd_mask);
	s->conn_count -= 1;
	list_del(&conn->list);
	close(conn->conn_fd);
	free(conn);
}

void socks_del_remote(struct socks_server_context *s, struct socks_remote_context *remote) {
	if (remote->conn_entry != NULL) {
		remote->conn_entry->remote = NULL;
	}
	socks_fd_set_del_fd(s->ss_allfd_set, remote->remote_fd, remote->fd_mask);
	close(remote->remote_fd);
	list_del(&remote->list);
	free(remote);
}

int socks_handshake_handle(struct socks_conn_context *conn) {
	ssize_t ret;
	struct buffer *buf = conn->server_entry->buf;

	ret = recv(conn->conn_fd, buf->data, 262, 0);
	if (ret <= 0) {
		goto err;
	}
	if (buf->data[0] != 0x05) {
		goto err;
	}
	if (buf->data[1] == 0) {
		goto err;
	}
	printf("client methods num: %d\n", buf->data[1]);
	/* TODO: 检查客户端支持的认证机制 */
	buf->data[0] = 0x05;
	buf->data[1] = 0x0; /* NO AUTHENTICATION REQUIRED */
	ret = send(conn->conn_fd, buf->data, 2, 0);
	if (ret != 2) {
		goto err;
	}
	conn->conn_state = CONNECTING;
	return 0;
err:
	debug_print("handshake failed: %s", strerror(errno));
	socks_server_del_conn(conn->server_entry, conn);
	return -1;
}

int socks_request_handle(struct socks_conn_context *conn, struct socks_conn_info *remote_info) {
	/* TODO */
	struct socks_request_frame request;
	struct socks_server_context *server = conn->server_entry;
	struct buffer *buf = server->buf;
	int ret;

	if (socks_get_requests(&request, conn->conn_fd, conn) == NULL) {
		debug_print("ss_get_requests() failed: %s", strerror(errno));
		return -1;
	}
	if (get_addr_info(&request, remote_info) == NULL) {
		debug_print("get_addr_info() failed: %s", strerror(errno));
		return -1;
	}
	buf->data[0] = 0x5;
	buf->data[1] = 0x0;
	buf->data[2] = 0x0;
	buf->data[3] = request.atyp;
	int s_addr = inet_aton("0.0.0.0", NULL);
	uint32_t us_addr = htonl(s_addr);
	memcpy(&buf->data[4], &us_addr, 4);
	//buf->data[4] = 0x1;
	buf->data[4 + 4] = 0x19;
	buf->data[4 + 5] = 0x19;
	buf->used = 10;
	ret = server->socks_send(conn->conn_fd, buf->data, buf->used, 0, conn);
	if (ret != buf->used) {
		debug_print("send return %d: %s", (int)ret, strerror(errno));
		return -1;
	}
	return 0;
}

void socks_loop(struct socks_server_context *server) {
	int events_num;
	struct socks_io_event *event;
	int fd;
	int i;

	while (1) {
		events_num = socks_poll(server);
		for (i = 0; i < events_num; i += 1) {
			if (server->fd_state[i].type == SOCKS_SERVER_CONTEXT) {
				/* accept */
				event = &server->io_proc;
				fd = server->sock_fd;
			} else if (server->fd_state[i].type == SOCKS_CONN_CONTEXT) {
				/* recv */
				event = &((struct socks_conn_context *)server->fd_state[i].context_ptr)->io_proc;
				fd = ((struct socks_conn_context *)server->fd_state[i].context_ptr)->conn_fd;
			} else if (server->fd_state[i].type == SOCKS_REMOTE_CONTEXT) {
				/* recv */
				event = &((struct socks_remote_context *)server->fd_state[i].context_ptr)->io_proc;
				fd = ((struct socks_remote_context *)server->fd_state[i].context_ptr)->remote_fd;
			}
			if (event->mask & AE_READABLE && event->rfproc != NULL) {
				event->rfproc(server->fd_state[i].context_ptr, fd, event->para, event->mask);
			}
		}
	}
}

void socks_server_set_handle(struct socks_server_context *server, int mask, socks_ioproc *r_callback, socks_ioproc *w_callback, void *para) {
	
	struct socks_io_event *event = &server->io_proc;
	memset(event, 0, sizeof(*event));
	event->mask = mask;
	event->rfproc = r_callback;
	event->wfproc = w_callback;
	event->para = para;
}

void socks_conn_set_handle(struct socks_conn_context *conn, int mask, socks_ioproc *r_callback, socks_ioproc *w_callback, void *para) {
	struct socks_io_event *event = &conn->io_proc;

	memset(event, 0, sizeof(*event));
	event->mask = mask;
	event->rfproc = r_callback;
	event->wfproc = w_callback;
	event->para = para;
}