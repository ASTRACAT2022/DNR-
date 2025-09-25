#include <ctime>
#include <time.h>
#include <stdio.h>
#include <resolv.h>
#include <memory.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <cassert>
#include <cctype>
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>

#include <unbound.h>

#include "config.h"

#define RX_BUFF_SIZE		4096
#define TX_BUFF_SIZE		4096

// Simplified statistic entry
struct statistic_enrty {
	unsigned int rx_query;
	unsigned int tx_response;
    unsigned int resolve_error;
    unsigned int resolve_secure;
    unsigned int resolve_bogus;
};

// Kept for packet building compatibility
struct question_entry {
	std::string qname;
	unsigned short qtype;
	unsigned short qclass;
};

// Global variables
struct ub_ctx* ctx = NULL;
unsigned char sendbuf[TX_BUFF_SIZE];
unsigned char *pspos = sendbuf;
unsigned char recvbuf[RX_BUFF_SIZE];
statistic_enrty ss;
char *remote_addr = NULL;
int lfd = -1;
timespec now = {0,0};

// options
in_addr bind_address = { INADDR_ANY };
unsigned short bind_port = 5099;

// Forward declarations
void print_help();
bool create_socket(int& fd, sockaddr_in* addr);
void handle_signal(int signal);
void handle_request(ns_msg& handle, const sockaddr_in& addr, const in_addr& local_addr, unsigned int ifindex);
void handle_packet(msghdr *msg, int size);
void build_error_packet(unsigned short rcode, const question_entry& question, bool rd_bit);
void send_packet(const sockaddr_in& addr, unsigned short id, const in_addr* local_addr, unsigned int ifindex);
bool parse_option(int argc, char **argv);

void print_help() {
	printf("AstracatDNR - Simple recursive DNS server (libunbound based)\n");
	printf("Usage: fastdns [-p port] [-h]\n");
	printf("Options:\n");
	printf("  -p port     Port to listen on (default: 5099)\n");
	printf("  -h          Show this help message\n");
}

void handle_signal(int signal) {
	syslog(LOG_INFO, "--- Statistics ---");
	syslog(LOG_INFO, "Query received    : %u", ss.rx_query);
	syslog(LOG_INFO, "Response send     : %u", ss.tx_response);
    syslog(LOG_INFO, "Resolve errors    : %u", ss.resolve_error);
    syslog(LOG_INFO, "Secure answers    : %u", ss.resolve_secure);
    syslog(LOG_INFO, "Bogus answers     : %u", ss.resolve_bogus);
}

int main(int argc, char **argv) {
	openlog("fastdns", LOG_PID|LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_INFO, "DNR starting up");

	if (parse_option(argc, argv) == false) return -1;
	syslog(LOG_INFO, "Options parsed");

	srand(time(0));
	memset(&ss, 0, sizeof(ss));

    ctx = ub_ctx_create();
    if (!ctx) {
        syslog(LOG_ERR, "Failed to create unbound context");
        return -1;
    }
    int retval;
    if ((retval = ub_ctx_add_ta_file(ctx, "/etc/unbound/root.key")) != 0) {
        syslog(LOG_WARNING, "Failed to add trust anchor file: %s. DNSSEC validation may not work.", ub_strerror(retval));
    }

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = bind_address;
	addr.sin_port = htons(bind_port);
	if (create_socket(lfd, &addr) == false) {
        ub_ctx_delete(ctx);
        return -1;
    }
	syslog(LOG_INFO, "Listening socket created");

	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &handle_signal;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		syslog(LOG_ERR, "Failed to setup signal handler!");
        close(lfd);
        ub_ctx_delete(ctx);
		return -1;
	}

	fd_set readfds, errorfds;
	int maxfd = lfd + 1;

	while (true) {
		FD_ZERO(&readfds);
		FD_ZERO(&errorfds);
		FD_SET(lfd, &readfds);
		FD_SET(lfd, &errorfds);

		struct timeval tv = {5, 0};

		if (select(maxfd, &readfds, NULL, &errorfds, &tv) < 0) {
			if (errno == EINTR) continue;
			syslog(LOG_ERR, "select encountered an error %d!", errno);
			break;
		}

		if (FD_ISSET(lfd, &errorfds)) {
			syslog(LOG_ERR, "socket error!");
			break;
		}

        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
			syslog(LOG_ERR, "clock_gettime encountered an error %d!", errno);
			break;
		}

		if (FD_ISSET(lfd, &readfds)) {
			iovec iov[1];
			msghdr msg;
			char control[CMSG_SPACE(sizeof(in_pktinfo))];
			iov[0].iov_base = recvbuf;
			iov[0].iov_len = sizeof(recvbuf);
			msg.msg_control = control;
			msg.msg_controllen = sizeof(control);
			msg.msg_flags = 0;
			msg.msg_name = &addr;
			msg.msg_namelen = sizeof(addr);
			msg.msg_iov = iov;
			msg.msg_iovlen = 1;
			int rc = recvmsg(lfd, &msg, 0);
			if (rc >= 0) {
				remote_addr = inet_ntoa(addr.sin_addr);
				if (addr.sin_port == 0) syslog(LOG_NOTICE, "Drop packet received from %s:%d", remote_addr, ntohs(addr.sin_port));
				else if (msg.msg_flags & MSG_TRUNC) syslog(LOG_NOTICE, "Drop truncated packet received from %s", remote_addr);
				else if (rc == 0) syslog(LOG_NOTICE, "Drop empty packet received from %s:%d", remote_addr, ntohs(addr.sin_port));
				else handle_packet(&msg, rc);
			}
			else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				syslog(LOG_ERR, "recvmsg encountered an error %d!", errno);
				break;
			}
		}
	}

    close(lfd);
    ub_ctx_delete(ctx);
	syslog(LOG_INFO, "exit...");
	return 0;
}

bool create_socket(int& fd, sockaddr_in* addr) {
	fd = socket(AF_INET , SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		syslog(LOG_ERR, "Can't create udp socket!");
		return false;
	}
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		syslog(LOG_ERR, "fcntl get flags failed!");
		return false;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		syslog(LOG_ERR, "fcntl set flags failed!");
		return false;
	}
	if (addr && bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
		syslog(LOG_ERR, "bind on port %d failed!", ntohs(addr->sin_port));
		return false;
	}
	int opt = 1;
	if (addr && setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) < 0) {
		syslog(LOG_ERR, "setsockopt(IP_PKTINFO) failed!");
		return false;
	}
	return true;
}

void handle_request(ns_msg& handle, const sockaddr_in& addr, const in_addr& local_addr, unsigned int ifindex) {
    ns_rr rr_q;
    question_entry question;
    ss.rx_query++;

    if (ns_parserr(&handle, ns_s_qd, 0, &rr_q) < 0) {
        syslog(LOG_INFO, "Failed to parse question in packet from %s", remote_addr);
        return;
    }
    const char* qname_ptr = ns_rr_name(rr_q);
    question.qname = qname_ptr;
    question.qtype = ns_rr_type(rr_q);
    question.qclass = ns_rr_class(rr_q);

    struct ub_result* result = NULL;
    int retval = ub_resolve(ctx, question.qname.c_str(), question.qtype, question.qclass, &result);

    if (retval != 0) {
        syslog(LOG_INFO, "resolve error for %s: %s", question.qname.c_str(), ub_strerror(retval));
        ss.resolve_error++;
        build_error_packet(ns_r_servfail, question, ns_msg_getflag(handle, ns_f_rd));
    } else if (result->bogus) {
        syslog(LOG_NOTICE, "BOGUS result for %s: %s", question.qname.c_str(), result->why_bogus);
        ss.resolve_bogus++;
        build_error_packet(ns_r_servfail, question, ns_msg_getflag(handle, ns_f_rd));
    } else {
        if (result->secure) {
            ss.resolve_secure++;
        }

        if (result->answer_len > sizeof(sendbuf)) {
            syslog(LOG_WARNING, "answer packet too large from libunbound (%d bytes), sending SERVFAIL", result->answer_len);
            build_error_packet(ns_r_servfail, question, ns_msg_getflag(handle, ns_f_rd));
        } else {
            memcpy(sendbuf, result->answer_packet, result->answer_len);
            pspos = sendbuf + result->answer_len;
        }
    }

    send_packet(addr, ns_msg_id(handle), &local_addr, ifindex);
    ss.tx_response++;

    if (result) {
        ub_resolve_free(result);
    }
}

void handle_packet(msghdr *msg, int size) {
	ns_msg handle;
	if (ns_initparse(recvbuf, size, &handle) < 0) return;
	if (ns_msg_count(handle, ns_s_qd) < 1) return;
	if (ns_msg_getflag(handle, ns_f_opcode) != 0) return;
	if (ns_msg_getflag(handle, ns_f_qr)) {
        syslog(LOG_NOTICE, "Drop response packet received from %s", remote_addr);
		return;
	}

	in_addr local_addr = {0};
	unsigned int ifindex = 0;
	cmsghdr *cmptr;
	for (cmptr = CMSG_FIRSTHDR(msg); cmptr; cmptr = CMSG_NXTHDR(msg, cmptr)) {
		if (cmptr->cmsg_level != IPPROTO_IP || cmptr->cmsg_type != IP_PKTINFO) continue;
		const in_pktinfo* pi = (const in_pktinfo*)CMSG_DATA(cmptr);
		local_addr = pi->ipi_addr;
		ifindex = pi->ipi_ifindex;
		break;
	}
	if (cmptr) handle_request(handle, *(sockaddr_in*)(msg->msg_name), local_addr, ifindex);
	else syslog(LOG_WARNING, "Unable to get in_pktinfo in packet received from %s", remote_addr);
}

void send_packet(const sockaddr_in& addr, unsigned short id, const in_addr* local_addr, unsigned int ifindex) {
	HEADER *ph = (HEADER *)sendbuf;
	ph->id = htons(id);
	iovec iov[1];
	msghdr msg;
	char control[CMSG_SPACE(sizeof(in_pktinfo))];
	iov[0].iov_base = sendbuf;
	iov[0].iov_len = pspos - sendbuf;
	msg.msg_flags = 0;
	msg.msg_name = (void *)&addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	if (local_addr) {
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);
		memset(&control, 0, sizeof(control));
		cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
		in_pktinfo *pi = (in_pktinfo*)CMSG_DATA(cmsg);
		pi->ipi_ifindex = ifindex;
		pi->ipi_spec_dst = *local_addr;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}
    sendmsg(lfd, &msg, 0);
}

void build_error_packet(unsigned short rcode, const question_entry& question, bool rd_bit) {
	HEADER *ph = (HEADER *)sendbuf;
	const unsigned char *dnptrs[2], **lastdnptr;
	unsigned char* psend = sendbuf+sizeof(sendbuf);
	int n;
	pspos = (unsigned char *)(ph + 1);
	lastdnptr = dnptrs + sizeof(dnptrs) / sizeof(dnptrs[0]);
	memset(sendbuf,0,sizeof(sendbuf));
	dnptrs[0]=sendbuf;
	dnptrs[1]=NULL;
	ph->qr = 1;
	ph->rd = rd_bit;
	ph->ra = 1;
	ph->rcode = rcode;
    ph->ad = 0;

	if (psend - pspos < QFIXEDSZ) { pspos = sendbuf; return; }
	if ((n = ns_name_compress(question.qname.c_str(), pspos, psend - pspos - QFIXEDSZ, dnptrs, lastdnptr)) < 0) { pspos = sendbuf; return; }
	pspos += n;
	ns_put16(question.qtype, pspos);	pspos += INT16SZ;
	ns_put16(question.qclass, pspos);	pspos += INT16SZ;
	ph->qdcount = htons(1);
    ph->ancount = 0;
    ph->nscount = 0;
    ph->arcount = 0;
}

bool parse_option(int argc, char **argv) {
    int c;
    while ((c = getopt(argc, argv, "p:h")) != -1) {
        switch (c) {
            case 'p':
                bind_port = atoi(optarg);
                if (bind_port == 0) {
                    fprintf(stderr, "Invalid port number: %s\n", optarg);
                    return false;
                }
                break;
            case 'h':
            default:
                print_help();
                return false;
        }
    }
    return true;
}