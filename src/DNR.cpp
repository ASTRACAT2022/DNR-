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
#include <assert.h>
#include <ctype.h>
#include <unordered_map>
#include <vector>
#include <list>
#include <set>
#include <string>
#include <algorithm>
#include "config.h"

#define RESPONSE_MAX_ANSWER_RR	32
#define QUESTION_MAX_REQUEST	32
#define RX_BUFF_SIZE		4096
#define TX_BUFF_SIZE		4096

struct statistic_enrty {
	unsigned int rx_query_edns;
	unsigned int rx_query;
	unsigned int tx_query;
	unsigned int query_retry;
	unsigned int rx_response;
	unsigned int rx_response_accepted;
	unsigned int tx_response;
	unsigned int total_request;
	unsigned int request_timeout;
	unsigned int cache_added;
	unsigned int cache_replaced;
	unsigned int cache_timeout;
	unsigned int cache_refresh;
	unsigned int cache_max;
};

// Operators for sockaddr_in to be used in maps
bool operator<(const sockaddr_in& a, const sockaddr_in& b) {
	if (a.sin_addr.s_addr != b.sin_addr.s_addr) return a.sin_addr.s_addr < b.sin_addr.s_addr;
	return a.sin_port < b.sin_port;
}

bool operator==(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

namespace std {
    template <>
    struct hash<sockaddr_in> {
        size_t operator()(const sockaddr_in& s) const {
            size_t h1 = std::hash<uint32_t>()(s.sin_addr.s_addr);
            size_t h2 = std::hash<uint16_t>()(s.sin_port);
            return h1 ^ (h2 << 1);
        }
    };
}

// Operators for timespec to be used in maps
bool operator<(const timespec& a, const timespec& b) {
	if (a.tv_sec != b.tv_sec) return a.tv_sec < b.tv_sec;
	return a.tv_nsec < b.tv_nsec;
}

bool operator==(const timespec& a, const timespec& b) {
    return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}

// Hash for timespec
struct timespec_hash {
    size_t operator()(const timespec& ts) const {
        return std::hash<long>()(ts.tv_sec) ^ (std::hash<long>()(ts.tv_nsec) << 1);
    }
};


struct ns_list {
	std::string scope;
	std::unordered_map<sockaddr_in, unsigned short> addrs;
};

struct question_entry {
	std::string qname;
	unsigned short qtype;
	unsigned short qclass;

	bool operator<(const question_entry& rhs) const {
		if (qtype != rhs.qtype) return qtype < rhs.qtype;
		if (qclass != rhs.qclass) return qclass < rhs.qclass;
		if (qname.size() != rhs.qname.size()) return qname.size() < rhs.qname.size();
		return qname.compare(rhs.qname) < 0;
	}

	bool operator==(const question_entry& rhs) const {
		return qtype == rhs.qtype && qclass == rhs.qclass && qname == rhs.qname;
	}

	bool operator!=(const question_entry& rhs) const {
		return !(*this == rhs);
	}
};

namespace std {
    template <>
    struct hash<question_entry> {
        size_t operator()(const question_entry& q) const {
            size_t h1 = hash<string>()(q.qname);
            size_t h2 = hash<unsigned short>()(q.qtype);
            size_t h3 = hash<unsigned short>()(q.qclass);
            return h1 ^ (h2 << 1) ^ (h3 << 2);
        }
    };
}

struct resource_entry {
	question_entry rq;
	time_t rexpiry;
	std::string rdata;
	unsigned short rperf; // for MX record
};

struct cache_entry {
	question_entry question;
	time_t last_update;
	time_t last_use;
	time_t least_expiry;
	std::list<resource_entry> rrs;
};

struct remote_source {
	sockaddr_in addr;
	in_addr local_addr;
	unsigned int ifindex;
	unsigned short id;
	bool do_bit;
	bool rd_bit;
};

struct local_source {
	question_entry oq;
	unsigned int progress;
	unsigned int base_progress;
	bool need_answer;
};

struct request_entry {
	question_entry question;
	question_entry nq;
	ns_list ns;
	unsigned int progress;
	time_t rexpiry;
	timespec lastsend;
	unsigned int retry;
	std::vector<resource_entry> anrr;
	std::list<remote_source> rlist;
	std::unordered_map<question_entry, local_source> llist;
	bool use_cache;
	unsigned short client_payload_size;
	unsigned short rcode;
};

// Using unordered_map for better performance (O(1) average case)
std::unordered_map<question_entry, cache_entry> cache_map;
std::unordered_map<time_t, std::set<cache_entry*>> cache_expiry_map;
std::unordered_map<question_entry, request_entry> request_map;
std::unordered_map<time_t, std::set<request_entry*>> request_expiry_map;
std::unordered_map<timespec, std::set<request_entry*>, timespec_hash> query_expiry_map;

unsigned char sendbuf[NS_PACKETSZ];
unsigned char *pspos = sendbuf;
unsigned char *psend = sendbuf+sizeof(sendbuf);
unsigned char recvbuf[RX_BUFF_SIZE];
statistic_enrty ss;
ns_list root_addrs;
char *remote_addr = NULL;
int lfd = -1;
int rfd = -1;
timespec now = {0,0};

// Default options
in_addr bind_address = { INADDR_ANY };
unsigned short bind_port = 53;
time_t cache_update_ttl = 180;
time_t cache_update_interval = 60;
time_t cache_update_min_ttl = 900;
unsigned int cache_soft_watermark = 50000;
time_t cache_soft_lru = 604800; // 7 days
unsigned int cache_hard_watermark = 100000;
unsigned int request_timeout = 5;
unsigned int query_timeout = 500;
unsigned int query_retry = 3;

void print_help();
timespec timespec_add(const timespec& a, int ms);
long long timespec_diff(const timespec& a, const timespec& b);
bool create_socket(int& fd, sockaddr_in* addr);
void init_root();
void handle_signal(int signal);
bool add_response_cache_entry(ns_msg& handle, ns_rr& rr, const std::string& scope, std::unordered_map<question_entry, cache_entry>& entries, unsigned short& rrtype);
void handle_response(ns_msg& handle, const sockaddr_in& addr);
bool add_request(const question_entry& question, const question_entry* oq, unsigned int progress, const sockaddr_in* addr, const in_addr* local_addr, unsigned int ifindex, unsigned short id,  bool do_bit, bool rd_bit, bool need_answer, bool use_cache, request_entry*& pentry);
void handle_request(ns_msg& handle, const sockaddr_in& addr, const in_addr& local_addr, unsigned int ifindex);
void handle_packet(msghdr *msg, int size, bool local);
void build_packet(bool query, unsigned short rcode, const question_entry& question, const std::vector<resource_entry>* anrr, unsigned short adrrc, unsigned short client_payload_size, bool do_bit, bool rd_bit = false);
void send_packet(const sockaddr_in& addr, unsigned short id, const in_addr* local_addr, unsigned int ifindex, bool local);
bool get_answer(question_entry& question, std::vector<resource_entry>& rr, bool use_cache);
unsigned short add_additional_answer(std::vector<resource_entry>& rr);
void find_nameserver(const question_entry& question, ns_list& ns, std::set<std::string>& ns_with_no_addr);
void update_request_lastsend(request_entry& request, bool retry, bool delete_only);
bool try_complete_request(request_entry& request, bool no_more_data, bool no_domain, unsigned int progress);
void check_expiry();
bool parse_option(int argc, char **argv);

void print_help() {
	printf("ASTRACAT DNR - High-performance recursive DNS server\n");
	printf("Usage: DNR [-p port] [-h]\n");
	printf("Options:\n");
	printf("  -p <port>   Port to listen on (default: 53)\n");
	printf("  -h          Show this help message\n");
}

void handle_signal(int signal) {
	syslog(LOG_INFO, "--- Statistics ---");
	syslog(LOG_INFO, "Query received    : %u", ss.rx_query);
	syslog(LOG_INFO, "EDNS Query received : %u", ss.rx_query_edns);
	syslog(LOG_INFO, "Query send        : %u", ss.tx_query);
	syslog(LOG_INFO, "Query retry       : %u", ss.query_retry);
	syslog(LOG_INFO, "Response received : %u", ss.rx_response);
	syslog(LOG_INFO, "Response accepted : %u", ss.rx_response_accepted);
	syslog(LOG_INFO, "Response send     : %u", ss.tx_response);
	syslog(LOG_INFO, "Total request     : %u", ss.total_request);
	syslog(LOG_INFO, "Request timeout   : %u", ss.request_timeout);
	syslog(LOG_INFO, "Cache added       : %u", ss.cache_added);
	syslog(LOG_INFO, "Cache replaced    : %u", ss.cache_replaced);
	syslog(LOG_INFO, "Cache timeout     : %u", ss.cache_timeout);
	syslog(LOG_INFO, "Cache refresh     : %u", ss.cache_refresh);
	syslog(LOG_INFO, "Max cache size    : %u", ss.cache_max);
	syslog(LOG_INFO, "--- Status ---");
	syslog(LOG_INFO, "Current cache size: %zu", cache_map.size());
	syslog(LOG_INFO, "Pending request   : %zu", request_map.size());
}

int main(int argc, char **argv) {
	openlog("DNR", LOG_PID|LOG_CONS, LOG_DAEMON);
	syslog(LOG_INFO, "ASTRACAT DNR starting up...");

	if (!parse_option(argc, argv)) {
        return 1;
    }

	srand(time(0));
	memset(&ss, 0, sizeof(ss));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = bind_address;
	addr.sin_port = htons(bind_port);

	if (!create_socket(lfd, &addr)) return 1;
	syslog(LOG_INFO, "Listening socket created on port %d.", bind_port);

	if (!create_socket(rfd, NULL)) return 1;
	syslog(LOG_INFO, "Remote communication socket created.");

	init_root();
	syslog(LOG_INFO, "Root hints initialized.");

	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &handle_signal;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		syslog(LOG_ERR, "Failed to setup signal handler: %m");
		return 1;
	}

	fd_set readfds, errorfds;
	int maxfd = std::max(lfd, rfd) + 1;
	timespec last_check = {0,0};

	while (true) {
		FD_ZERO(&readfds);
		FD_ZERO(&errorfds);
		FD_SET(lfd, &readfds);
		FD_SET(rfd, &readfds);
		FD_SET(lfd, &errorfds);
		FD_SET(rfd, &errorfds);

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 1000; // 1ms timeout for high responsiveness

		int ret = select(maxfd, &readfds, NULL, &errorfds, &tv);
        if (ret < 0) {
			if (errno == EINTR) continue;
			syslog(LOG_ERR, "select() failed: %m");
			return 1;
		}

		if (FD_ISSET(lfd, &errorfds) || FD_ISSET(rfd, &errorfds)) {
			syslog(LOG_ERR, "Socket error detected by select().");
			return 1;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
			syslog(LOG_ERR, "clock_gettime() failed: %m");
			return 1;
		}

        if (ret > 0) {
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

            int fd = FD_ISSET(lfd, &readfds) ? lfd : rfd;
            int rc = recvmsg(fd, &msg, 0);

            if (rc > 0) {
                remote_addr = inet_ntoa(addr.sin_addr);
                if (addr.sin_port == 0) {
                    syslog(LOG_NOTICE, "Dropped packet from %s with port 0.", remote_addr);
                } else if (msg.msg_flags & MSG_TRUNC) {
                    syslog(LOG_NOTICE, "Dropped truncated packet from %s.", remote_addr);
                } else {
                    handle_packet(&msg, rc, fd == lfd);
                }
            } else if (rc < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                syslog(LOG_ERR, "recvmsg() failed: %m");
                return 1;
            }
        }

		if (timespec_diff(now, last_check) >= 10) { // Check expiry every 10ms
			check_expiry();
			last_check = now;
		}
	}

	closelog();
	return 0;
}

timespec timespec_add(const timespec& a, int ms) {
	timespec result = a;
	result.tv_sec += ms / 1000;
	result.tv_nsec += (ms % 1000) * 1000000;
	if (result.tv_nsec >= 1000000000) {
		result.tv_sec++;
		result.tv_nsec -= 1000000000;
	}
	return result;
}

long long timespec_diff(const timespec& a, const timespec& b) {
	return (a.tv_sec - b.tv_sec) * 1000LL + (a.tv_nsec - b.tv_nsec) / 1000000LL;
}

bool create_socket(int& fd, sockaddr_in* addr) {
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		syslog(LOG_CRIT, "socket() failed: %m");
		return false;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		syslog(LOG_CRIT, "fcntl() failed: %m");
		close(fd);
		return false;
	}

	if (addr) {
        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            syslog(LOG_WARNING, "setsockopt(SO_REUSEADDR) failed: %m");
        }
		if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
			syslog(LOG_CRIT, "bind() to port %d failed: %m", ntohs(addr->sin_port));
			close(fd);
			return false;
		}
		if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) < 0) {
			syslog(LOG_CRIT, "setsockopt(IP_PKTINFO) failed: %m");
			close(fd);
			return false;
		}
	}
	return true;
}

void init_root() {
	root_addrs.scope = "";
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	// Hardcoded root servers list
	addr.sin_addr.s_addr = inet_addr("198.41.0.4");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("199.9.14.201");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("192.33.4.12");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("199.7.91.13");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("192.203.230.10");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("192.5.5.241");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("192.112.36.4");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("198.97.190.53");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("192.36.148.17");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("192.58.128.30");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("193.0.14.129");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("199.7.83.42");	root_addrs.addrs.insert({addr, 0});
	addr.sin_addr.s_addr = inet_addr("202.12.27.33");	root_addrs.addrs.insert({addr, 0});
}

bool add_response_cache_entry(ns_msg& handle, ns_rr& rr, const std::string& scope, std::unordered_map<question_entry, cache_entry>& entries, unsigned short& rrtype) {
	char domain_name[MAXDNAME];
	resource_entry r;
	r.rq.qname = ns_rr_name(rr);
	r.rq.qtype = rrtype = ns_rr_type(rr);
	r.rq.qclass = ns_rr_class(rr);
	r.rexpiry = now.tv_sec + ns_rr_ttl(rr);
	std::transform(r.rq.qname.begin(), r.rq.qname.end(), r.rq.qname.begin(), ::tolower);

	if (r.rq.qname.size() < scope.size() || r.rq.qname.compare(r.rq.qname.size() - scope.size(), scope.size(), scope) != 0) {
		return false;
	}

	const unsigned char* pdata = ns_rr_rdata(rr);
	unsigned int sdata = ns_rr_rdlen(rr);
	if (sdata == 0) return false;

	switch (r.rq.qtype) {
	case T_MX:
		if (sdata <= 2) return false;
		r.rperf = ns_get16(pdata);
		pdata += 2;
		sdata -= 2;
	case T_NS:
	case T_CNAME:
	case T_PTR:
		if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), pdata, domain_name, sizeof(domain_name)) != (int)sdata) {
			return false;
		}
		r.rdata = domain_name;
		std::transform(r.rdata.begin(), r.rdata.end(), r.rdata.begin(), ::tolower);
		break;
	case T_TXT:
	case T_A:
	case T_AAAA:
		r.rdata.assign((const char*)pdata, sdata);
		break;
	case T_SOA:
		return false; // Ignore SOA
	default:
		return false; // Ignore unsupported types
	}

	bool exist = entries.count(r.rq);
	cache_entry& cache = entries[r.rq];
	if (!exist) {
		cache.question = r.rq;
		cache.last_update = now.tv_sec + cache_update_min_ttl;
		cache.last_use = now.tv_sec;
	}
	cache.rrs.push_back(r);
	return true;
}

void handle_response(ns_msg& handle, const sockaddr_in& addr) {
	ns_rr rr;
	question_entry question;
	unsigned short rcode = ns_msg_getflag(handle, ns_f_rcode);
	unsigned short id = ns_msg_id(handle);
	ss.rx_response++;

	if (ns_parserr(&handle, ns_s_qd, 0, &rr) < 0) return;

	question.qname = ns_rr_name(rr);
	question.qtype = ns_rr_type(rr);
	question.qclass = ns_rr_class(rr);
	std::transform(question.qname.begin(), question.qname.end(), question.qname.begin(), ::tolower);

	if (rcode != NXDOMAIN && rcode != NOERROR) {
		if (rcode == ns_r_servfail && request_map.count(question)) {
			request_entry& request = request_map.at(question);
			request.rcode = ns_r_servfail;
			try_complete_request(request, true, false, request.progress);
		}
		return;
	}

	if (request_map.count(question) == 0) return;
	request_entry& request = request_map.at(question);
	if (request.ns.addrs.count(addr) == 0 || request.ns.addrs.at(addr) != id) return;

	ss.rx_response_accepted++;

    std::unordered_map<question_entry, cache_entry> entries;
    unsigned short rrtype;
	bool no_answer = true;
	bool no_ns = true, no_soa = true;

	for (int s = ns_s_an; s <= ns_s_ar; s++) {
        for (int i = 0; i < ns_msg_count(handle, (ns_sect)s); i++) {
            if (ns_parserr(&handle, (ns_sect)s, i, &rr) < 0) continue;
            add_response_cache_entry(handle, rr, request.ns.scope, entries, rrtype);
            if (s == ns_s_an && (rrtype == question.qtype || rrtype == T_CNAME)) no_answer = false;
            if (s == ns_s_ns) {
                if (rrtype == T_NS) no_ns = false;
                else if (rrtype == T_SOA) no_soa = false;
            }
        }
    }

	for (auto& pair : entries) {
		cache_entry& tmp_cache = pair.second;
		tmp_cache.least_expiry = 0;
		for (const auto& r : tmp_cache.rrs) {
			if (tmp_cache.least_expiry == 0 || tmp_cache.least_expiry > r.rexpiry) {
                tmp_cache.least_expiry = r.rexpiry;
            }
		}
		if (tmp_cache.least_expiry == 0) continue;

		if (cache_map.count(tmp_cache.question)) {
			cache_entry& old_cache = cache_map.at(tmp_cache.question);
			if (old_cache.least_expiry > tmp_cache.least_expiry) continue;
			tmp_cache.last_use = old_cache.last_use;

            auto it = cache_expiry_map.find(old_cache.least_expiry);
            if (it != cache_expiry_map.end()) {
                it->second.erase(&old_cache);
                if (it->second.empty()) {
                    cache_expiry_map.erase(it);
                }
            }
			ss.cache_replaced++;
		} else {
            ss.cache_added++;
        }

		cache_map[tmp_cache.question] = tmp_cache;
		cache_expiry_map[tmp_cache.least_expiry].insert(&cache_map.at(tmp_cache.question));
		if (cache_map.size() > ss.cache_max) ss.cache_max = cache_map.size();
	}

	bool no_more_data = no_soa || (no_ns && no_answer);
	bool no_domain = (rcode == NXDOMAIN);
	try_complete_request(request, no_more_data, no_domain, request.progress);
}

bool add_request(const question_entry& question, const question_entry* oq, unsigned int progress, const sockaddr_in* addr, const in_addr* local_addr, unsigned int ifindex, unsigned short id, bool do_bit, bool rd_bit, bool need_answer, bool use_cache, request_entry*& pentry) {
	pentry = nullptr;
	bool missing = false;

	if (request_map.find(question) == request_map.end()) {
		missing = true;
		request_entry request;
		request.question = question;
		request.nq = question;
		request.progress = oq ? progress : 0;
		request.rexpiry = now.tv_sec + request_timeout;
		request.lastsend = {0, 0};
		request.retry = 0;
		request.use_cache = use_cache;
		request.client_payload_size = 0;
		request.rcode = ns_r_noerror;

        auto pair = request_map.emplace(question, request);
        pentry = &pair.first->second;
		request_expiry_map[request.rexpiry].insert(pentry);
		ss.total_request++;
	} else {
        pentry = &request_map.at(question);
    }

	if (oq) {
		local_source& ls = pentry->llist[*oq];
		ls.oq = *oq;
		ls.progress = progress;
		ls.need_answer = need_answer;
		ls.base_progress = pentry->progress;
	} else if (addr) {
		remote_source rs = {*addr, *local_addr, ifindex, id, do_bit, rd_bit};
		pentry->rlist.push_back(rs);
	}
	return missing;
}

void handle_request(ns_msg& handle, const sockaddr_in& addr, const in_addr& local_addr, unsigned int ifindex) {
	ns_rr rr;
	question_entry question;
	ss.rx_query++;

	if (ns_parserr(&handle, ns_s_qd, 0, &rr) < 0) return;

	question.qname = ns_rr_name(rr);
	question.qtype = ns_rr_type(rr);
	question.qclass = ns_rr_class(rr);
	std::transform(question.qname.begin(), question.qname.end(), question.qname.begin(), ::tolower);

	bool do_bit = false;
	unsigned short client_payload_size = 512;
	if (ns_msg_count(handle, ns_s_ar) > 0) {
		for (int i = 0; i < ns_msg_count(handle, ns_s_ar); ++i) {
			if (ns_parserr(&handle, ns_s_ar, i, &rr) == 0 && ns_rr_type(rr) == ns_t_opt) {
				ss.rx_query_edns++;
				client_payload_size = ns_rr_class(rr);
				if (ns_rr_ttl(rr) & 0x8000) do_bit = true;
				break;
			}
		}
	}

	request_entry* pentry;
	if (add_request(question, NULL, 0, &addr, &local_addr, ifindex, ns_msg_id(handle), do_bit, ns_msg_getflag(handle, ns_f_rd), true, true, pentry)) {
		pentry->client_payload_size = client_payload_size;
		try_complete_request(*pentry, false, false, pentry->progress);
	}
}

void handle_packet(msghdr *msg, int size, bool local) {
	ns_msg handle;
	if (ns_initparse(recvbuf, size, &handle) < 0) return;
	if (ns_msg_count(handle, ns_s_qd) < 1) return;
	if (ns_msg_getflag(handle, ns_f_opcode) != ns_o_query) return;
	if (!!ns_msg_getflag(handle, ns_f_qr) == local) return;

	if (local) {
		in_addr local_addr = {0};
		unsigned int ifindex = 0;
		for (cmsghdr *cmptr = CMSG_FIRSTHDR(msg); cmptr; cmptr = CMSG_NXTHDR(msg, cmptr)) {
			if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO) {
				const in_pktinfo* pi = (const in_pktinfo*)CMSG_DATA(cmptr);
				local_addr = pi->ipi_addr;
				ifindex = pi->ipi_ifindex;
				handle_request(handle, *(sockaddr_in*)(msg->msg_name), local_addr, ifindex);
				return;
			}
		}
		syslog(LOG_WARNING, "Could not get packet info from local request from %s", remote_addr);
	} else {
		handle_response(handle, *(sockaddr_in*)(msg->msg_name));
	}
}

bool get_answer(question_entry& question, std::vector<resource_entry>& rr, bool use_cache) {
	for (int i = 0; i < 10; ++i) { // CNAME loop limit
		auto it = cache_map.find(question);
		if (it != cache_map.end() && (use_cache || it->second.least_expiry > now.tv_sec + cache_update_ttl)) {
			it->second.last_use = now.tv_sec;
			rr.insert(rr.end(), it->second.rrs.begin(), it->second.rrs.end());
			return true;
		}
		if (rr.size() >= RESPONSE_MAX_ANSWER_RR) return true;

		unsigned short qtype = question.qtype;
		question.qtype = T_CNAME;
		it = cache_map.find(question);
		if (it != cache_map.end() && (use_cache || it->second.least_expiry > now.tv_sec + cache_update_ttl)) {
			it->second.last_use = now.tv_sec;
			rr.insert(rr.end(), it->second.rrs.begin(), it->second.rrs.end());
			question.qname = rr.back().rdata;
			question.qtype = qtype;
		} else {
			question.qtype = qtype;
			return false;
		}
	}
	return false;
}

unsigned short add_additional_answer(std::vector<resource_entry>& rr) {
	unsigned short original_size = rr.size();
	for (unsigned short i = 0; i < original_size; i++) {
		if (rr[i].rq.qtype == T_MX || rr[i].rq.qtype == T_NS) {
			question_entry qa;
			qa.qname = rr[i].rdata;
			qa.qclass = rr[i].rq.qclass;
			qa.qtype = T_A;
			get_answer(qa, rr, true);
            qa.qtype = T_AAAA;
            get_answer(qa, rr, true);
		}
	}
	return rr.size() - original_size;
}

void find_nameserver(const question_entry& question, ns_list& ns, std::set<std::string>& ns_with_no_addr) {
	const char* pstr = question.qname.c_str();
	while (ns.addrs.empty() && ns_with_no_addr.empty()) {
		if (!pstr || *pstr == '\0') {
			ns = root_addrs;
			return;
		}

        question_entry testns;
		testns.qname = ns.scope = pstr;
        testns.qclass = C_IN;
		testns.qtype = T_NS;

		if (cache_map.count(testns)) {
			cache_entry& nscache = cache_map.at(testns);
			nscache.last_use = 0;
			for (const auto& n : nscache.rrs) {
                question_entry testa;
				testa.qname = n.rdata;
				testa.qclass = C_IN;
				testa.qtype = T_A;
				if (cache_map.count(testa)) {
					cache_entry& acache = cache_map.at(testa);
					acache.last_use = 0;
					for (const auto& a : acache.rrs) {
						if (a.rdata.size() == 4) {
							sockaddr_in addr = {0};
							addr.sin_family = AF_INET;
							addr.sin_port = htons(53);
							addr.sin_addr.s_addr = *((uint32_t*)a.rdata.c_str());
							ns.addrs.insert({addr, 0});
						}
					}
				} else {
                    ns_with_no_addr.insert(testa.qname);
                }
			}
			if (ns.addrs.empty() && (question.qtype == T_A || question.qtype == T_AAAA) && ns_with_no_addr.count(question.qname)) {
                ns_with_no_addr.clear();
            }
		}
		pstr = strchr(pstr, '.');
		if (pstr) pstr++;
	}
}

void update_request_lastsend(request_entry& request, bool retry, bool delete_only) {
	if (request.lastsend.tv_sec != 0) {
        auto it = query_expiry_map.find(request.lastsend);
        if (it != query_expiry_map.end()) {
            it->second.erase(&request);
            if (it->second.empty()) {
                query_expiry_map.erase(it);
            }
        }
		request.lastsend = {0, 0};
	}
	if (delete_only) return;

	if (retry) request.retry++;
	if (request.retry < query_retry) {
        request.lastsend = timespec_add(now, query_timeout);
        query_expiry_map[request.lastsend].insert(&request);
    }
}

bool try_complete_request(request_entry& request, bool no_more_data, bool no_domain, unsigned int progress) {
	if (request_map.find(request.question) == request_map.end() || request.progress > progress) {
        return false;
    }
	request.progress = progress;

	if (get_answer(request.nq, request.anrr, request.use_cache) || no_more_data || no_domain || request.progress > QUESTION_MAX_REQUEST) {
		request.progress++;

        std::unordered_map<question_entry, local_source> tmp_llist;
		tmp_llist.swap(request.llist);

		unsigned short adrrc = add_additional_answer(request.anrr);

		for (const auto& r : request.rlist) {
			ss.tx_response++;
			if (&r == &request.rlist.front()) {
                build_packet(false, (request.rcode != ns_r_noerror) ? request.rcode : (no_domain ? NXDOMAIN : NOERROR), request.question, &request.anrr, adrrc, request.client_payload_size, r.do_bit, r.rd_bit);
            }
			send_packet(r.addr, r.id, &r.local_addr, r.ifindex, true);
		}

		for (auto& pair : tmp_llist) {
			local_source& ls = pair.second;
			if (request_map.count(ls.oq) == 0) continue;
			request_entry& local_request = request_map.at(ls.oq);
			if ((no_more_data || no_domain) && !ls.need_answer) continue;
			if (local_request.progress != ls.progress) continue;
			try_complete_request(local_request, no_more_data, no_domain, local_request.progress + request.progress - ls.base_progress);
		}

        auto it_req_exp = request_expiry_map.find(request.rexpiry);
        if (it_req_exp != request_expiry_map.end()) {
            it_req_exp->second.erase(&request);
            if (it_req_exp->second.empty()) {
                request_expiry_map.erase(it_req_exp);
            }
        }

		update_request_lastsend(request, false, true);
		request_map.erase(request.question);
		return true;
	}

	if (request.nq != request.question) {
		request.ns.addrs.clear();
		update_request_lastsend(request, false, true);
		request.use_cache = true;

		request_entry* pentry;
		bool new_do_bit = request.rlist.empty() ? false : request.rlist.front().do_bit;
		bool new_rd_bit = request.rlist.empty() ? false : request.rlist.front().rd_bit;

		if (add_request(request.nq, &request.question, request.progress, NULL, NULL, 0, 0, new_do_bit, new_rd_bit, true, true, pentry)) {
            return try_complete_request(*pentry, false, false, pentry->progress);
        }
		return false;
	}

	std::set<std::string> ns_with_no_addr;
	ns_list new_list;
	find_nameserver(request.question, new_list, ns_with_no_addr);

	if (!new_list.addrs.empty()) {
		if (new_list.scope != request.ns.scope || new_list.scope.empty() || request.ns.addrs.empty()) {
			request.progress++;
			request.ns.addrs.clear();
		}
		build_packet(true, NOERROR, request.question, NULL, 0, 0, false, true);
		bool updated_lastsend = false;
		for (const auto& pair : new_list.addrs) {
			if (request.ns.addrs.find(pair.first) == request.ns.addrs.end()) {
                updated_lastsend = true;
                unsigned short new_id = rand();
                request.ns.addrs[pair.first] = new_id;
                ss.tx_query++;
                send_packet(pair.first, new_id, NULL, 0, false);
            }
		}
		if (updated_lastsend) update_request_lastsend(request, false, false);
	} else {
		request.ns.addrs.clear();
		update_request_lastsend(request, false, true);
	}
	request.ns.scope = new_list.scope;

	if (!ns_with_no_addr.empty()) {
		question_entry nsq;
		nsq.qclass = C_IN;
		nsq.qtype = T_A;
		std::unordered_map<question_entry, unsigned int> reqs;

		for (const auto& name : ns_with_no_addr) {
			nsq.qname = name;
			if (nsq == request.question) continue;

			request_entry* pentry;
            bool new_do_bit = request.rlist.empty() ? false : request.rlist.front().do_bit;
            bool new_rd_bit = request.rlist.empty() ? false : request.rlist.front().rd_bit;
			if (add_request(nsq, &request.question, request.progress, NULL, NULL, 0, 0, new_do_bit, new_rd_bit, false, true, pentry)) {
                reqs[nsq] = pentry->progress;
            }
		}

		for (const auto& pair : reqs) {
			if (request_map.count(pair.first) && request_map.at(pair.first).progress == pair.second) {
                try_complete_request(request_map.at(pair.first), false, false, request_map.at(pair.first).progress);
            }
		}
	}
	return false;
}

void send_packet(const sockaddr_in& addr, unsigned short id, const in_addr* local_addr, unsigned int ifindex, bool local) {
	int fd = local ? lfd : rfd;
	HEADER *ph = (HEADER *)sendbuf;
	ph->id = htons(id);

	iovec iov[1];
	iov[0].iov_base = sendbuf;
	iov[0].iov_len = pspos - sendbuf;

	msghdr msg = {0};
	msg.msg_name = (void *)&addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	char control[CMSG_SPACE(sizeof(in_pktinfo))];
	if (local_addr) {
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);
		cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
		in_pktinfo *pi = (in_pktinfo*)CMSG_DATA(cmsg);
		pi->ipi_ifindex = ifindex;
		pi->ipi_spec_dst = *local_addr;
	}

	if (sendmsg(fd, &msg, 0) < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        syslog(LOG_WARNING, "sendmsg() failed: %m");
    }
}

void build_packet(bool query, unsigned short rcode, const question_entry& question, const std::vector<resource_entry>* anrr, unsigned short adrrc, unsigned short client_payload_size, bool do_bit, bool rd_bit) {
	HEADER *ph = (HEADER *)sendbuf;
	const unsigned char *dnptrs[RESPONSE_MAX_ANSWER_RR + 2], **lastdnptr;

	memset(sendbuf, 0, sizeof(sendbuf));
	pspos = (unsigned char *)(ph + 1);
	lastdnptr = dnptrs + sizeof(dnptrs) / sizeof(dnptrs[0]);
	dnptrs[0] = sendbuf;
	dnptrs[1] = NULL;

	ph->qr = !query;
	ph->rd = query || rd_bit;
	ph->ra = !query;
	ph->rcode = rcode;

	int n = ns_name_compress(question.qname.c_str(), pspos, psend - pspos - QFIXEDSZ, dnptrs, lastdnptr);
	if (n < 0) return;
	pspos += n;
	ns_put16(question.qtype, pspos); pspos += INT16SZ;
	ns_put16(question.qclass, pspos); pspos += INT16SZ;
	ph->qdcount = htons(1);

	unsigned short ancount = 0, arcount = 0;
	if (anrr) {
        for (const auto& r : *anrr) {
            if (psend - pspos < RRFIXEDSZ) break;
            n = ns_name_compress(r.rq.qname.c_str(), pspos, psend - pspos - RRFIXEDSZ, dnptrs, lastdnptr);
            if (n < 0) break;
            pspos += n;

            ns_put16(r.rq.qtype, pspos); pspos += INT16SZ;
            ns_put16(r.rq.qclass, pspos); pspos += INT16SZ;
            ns_put32(r.rexpiry > now.tv_sec ? r.rexpiry - now.tv_sec : 0, pspos); pspos += INT32SZ;

            unsigned short *prsize = (unsigned short *)pspos;
            pspos += INT16SZ;
            unsigned short rsize = 0;

            switch (r.rq.qtype) {
            case T_MX:
                if (psend - pspos < INT16SZ) continue;
                ns_put16(r.rperf, pspos); pspos += INT16SZ; rsize += INT16SZ;
            case T_NS:
            case T_CNAME:
            case T_PTR:
                n = ns_name_compress(r.rdata.c_str(), pspos, psend - pspos, dnptrs, lastdnptr);
                if (n < 0) continue;
                pspos += n; rsize += n;
                break;
            case T_TXT:
            case T_A:
            case T_AAAA:
                if (psend - pspos < (int)r.rdata.size()) continue;
                memcpy(pspos, r.rdata.c_str(), r.rdata.size());
                pspos += r.rdata.size(); rsize += r.rdata.size();
                break;
            default:
                continue;
            }
            *prsize = htons(rsize);
            if (ancount + arcount < (unsigned short)anrr->size() - adrrc) ancount++; else arcount++;
        }
    }
	ph->ancount = htons(ancount);
	ph->arcount = htons(arcount);

	if (!query && client_payload_size > 512) {
		if (psend - pspos >= 11) {
			*pspos++ = 0;
			ns_put16(ns_t_opt, pspos); pspos += 2;
			ns_put16(client_payload_size, pspos); pspos += 2;
			ns_put32(do_bit ? 0x80000000 : 0, pspos); pspos += 4;
			ns_put16(0, pspos); pspos += 2;
			ph->arcount = htons(ntohs(ph->arcount) + 1);
		}
	}
}

void check_expiry() {
    // Check for timed out requests
    for (auto it = request_expiry_map.begin(); it != request_expiry_map.end(); ) {
        if (it->first <= now.tv_sec) {
            for (auto* r : it->second) {
                ss.request_timeout++;
                update_request_lastsend(*r, false, true);
                request_map.erase(r->question);
            }
            it = request_expiry_map.erase(it);
        } else {
            ++it;
        }
    }

    // Check for query retries
    for (auto it = query_expiry_map.begin(); it != query_expiry_map.end(); ) {
        if (it->first < now) {
            request_entry* r = *it->second.begin();
            ss.query_retry++;
            build_packet(true, NOERROR, r->question, NULL, 0, 0, false, true);
            for (const auto& pair : r->ns.addrs) {
                ss.tx_query++;
                send_packet(pair.first, pair.second, NULL, 0, false);
            }
            update_request_lastsend(*r, true, false); // This will re-insert it if retries are not exhausted
            it = query_expiry_map.erase(it); // Erase the old entry
        } else {
            break; // The map is ordered, so we can stop
        }
    }

    // Check for cache expiry and refresh
    for (auto it = cache_expiry_map.begin(); it != cache_expiry_map.end(); ) {
        if (it->first <= now.tv_sec + cache_update_ttl) {
            for (auto itc = it->second.begin(); itc != it->second.end(); ) {
                cache_entry* centry = *itc;
                if (centry->least_expiry <= now.tv_sec) {
                    ss.cache_timeout++;
                    cache_map.erase(centry->question);
                    itc = it->second.erase(itc);
                    continue;
                }

                if (centry->last_update <= now.tv_sec - cache_update_interval) {
                    if (centry->last_use != 0) {
                        if (cache_map.size() > cache_hard_watermark || (cache_map.size() > cache_soft_watermark && centry->last_use < now.tv_sec - cache_soft_lru)) {
                             ++itc;
                             continue;
                        }
                    }
                    ss.cache_refresh++;
                    centry->last_update = now.tv_sec;
                    request_entry* rentry;
                    if (add_request(centry->question, NULL, 0, NULL, NULL, 0, 0, false, true, false, false, rentry)) {
                        try_complete_request(*rentry, false, false, rentry->progress);
                    }
                }
                ++itc;
            }

            if (it->second.empty()) {
                it = cache_expiry_map.erase(it);
            } else {
                ++it;
            }
        } else {
            ++it;
        }
    }
}

bool parse_option(int argc, char **argv) {
    int c;
    while ((c = getopt(argc, argv, "p:h")) != -1) {
        switch (c) {
            case 'p':
                bind_port = atoi(optarg);
                if (bind_port <= 0 || bind_port > 65535) {
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