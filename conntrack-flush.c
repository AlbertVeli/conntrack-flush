/* Flush conntrack rules except those dports given as arguments
 *
 * Copyright (C) 2010-2017  Westermo Teleindustri AB
 *
 * Author(s): Albert Veli <albert.veli@westermo.se>
 *            Jonas Johansson <jonas.johansson@westermo.se>
 *            Joachim Nilsson <joachim.nilsson@westermo.se>
 *            Magnus Oberg <magnus.oberg@westermo.se>
 *
 * Note: This tool links against GPL'ed libraries, so effectively this
 *       code falls under the GPL.  However, Westermo releases this
 *       particular code under the ISC license.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

#define MAX_PORTS 42
#define UNUSED(x) x __attribute__ ((unused))

/* Program meta data */
extern char       *__progname;
static const char *doc = "Flush all contrack rules except those with dport given as argument";

/* Port list from the command line */
size_t         num_ports = 0;
unsigned short ports[MAX_PORTS];

static struct nfct_handle *cth, *ith;

unsigned int *local_ip = NULL;
int local_ip_cnt = 0;
int local_ip_allocated = 0;

int debug = 0;

int kept = 0;
int deleted = 0;

static int usage(int argc, char *argv[])
{
	int i;

	fprintf (stderr, "%s\n"
		 "------------------------------------------------------------------------------\n"
		 "Failed:\n"
		 "         %s ", doc, __progname);

	for (i = 1; i < argc; i++)
		fprintf(stderr, "%s ", argv[i]);

	fprintf (stderr, "\n\n"
		 "Usage:\n"
		 "         %s [--debug] PORT1 PORT2 ...\n"
		 "\n"
		 "Example:\n"
		 "         %s 22 80 443\n"
		 "------------------------------------------------------------------------------\n"
		 "Copyright (C) 2010-2017  Westermo Teleindustri AB\n", __progname, __progname);

	return 1;
}

static void add_ip(unsigned int ip)
{
	if (local_ip == NULL) {
		local_ip_allocated = 10;
		local_ip = malloc(sizeof(unsigned int) * local_ip_allocated);

	} else if (local_ip_cnt == local_ip_allocated) {
		local_ip_allocated *= 2;
		local_ip = realloc(local_ip, sizeof(unsigned int) * local_ip_allocated);
	}

	if (local_ip == NULL) {
		fprintf (stderr, "Out of memory!\n");
		exit(10);
	}

	local_ip[local_ip_cnt++] = ip;
}

static int ip_compare(const void *aptr, const void *bptr)
{
	unsigned int a = *((unsigned int *)aptr);
	unsigned int b = *((unsigned int *)bptr);

	if (a < b)
		return -1;
	if (a > b)
		return 1;

	return 0;
}

static void sort_ip()
{
	if (local_ip == NULL)
		return;

	qsort(local_ip, local_ip_cnt, sizeof(unsigned int), ip_compare);
}

static int find_ip_rec(unsigned int ip, unsigned int *arr, int size)
{
	int middle = size/2;
	int comp;

	if (size <= 0)
		return 0;

	comp = ip_compare(&ip, &arr[middle]);
	if (comp == 0)
		return 1;

	if (comp < 0)
		return find_ip_rec(ip, arr, middle);

	return find_ip_rec(ip, arr+(middle+1), size-(middle+1));
}

static int find_ip(unsigned int ip)
{
	return find_ip_rec(ip, local_ip, local_ip_cnt);
}

static int ip_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFA_MAX) < 0)
		return MNL_CB_OK;

	if (type == IFA_ADDRESS) {
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			return MNL_CB_ERROR;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

/* Called for each local interface address */
static int ip_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[IFLA_MAX+1] = {};
	struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
	struct in_addr *addr;
	char out[INET6_ADDRSTRLEN];

	if (ifa->ifa_family != AF_INET)
		return MNL_CB_OK;

	mnl_attr_parse(nlh, sizeof(*ifa), ip_attr_cb, tb);
	if (tb[IFA_ADDRESS]) {
		addr = (struct in_addr *)mnl_attr_get_payload(tb[IFA_ADDRESS]);

		if (debug) {
			inet_ntop(ifa->ifa_family, addr, out, sizeof(out));
			printf("Local IP: %s\n", out);
		}

		add_ip(ntohl(addr->s_addr));
	}
	return MNL_CB_OK;
}

/* Called for each conntrack entry */
static int ct_cb(enum nf_conntrack_msg_type UNUSED(type), struct nf_conntrack *ct, void UNUSED(*data))
{
	int keepit = 0;
	int i, res;
	unsigned int src, dst;
	unsigned short sport, dport;
	unsigned int repl_src, repl_dst;
	unsigned short repl_sport, repl_dport;

	dport = htons(nfct_get_attr_u16(ct, ATTR_PORT_DST));
	dst = htonl(nfct_get_attr_u32(ct, ATTR_IPV4_DST));

	/* Keep sessions with dst IP as one of our own IP and
	 * dport as one of the command arguments. Delete all
	 * other sessions */
	for (i = 0; i < num_ports; i++) {
		if (ports[i] == dport) {
			if (find_ip(dst))
				keepit = 1;
			break;
		}
	}

	if (debug) {
		src = htonl(nfct_get_attr_u32(ct, ATTR_IPV4_SRC));
		sport = htons(nfct_get_attr_u16(ct, ATTR_PORT_SRC));

		repl_src = htonl(nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC));
		repl_dst = htonl(nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST));
		repl_sport = htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
		repl_dport = htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST));

		printf("%s 0x%08x:%-5hu->0x%08x:%-5hu (0x%08x:%-5hu->0x%08x:%-5hu)\n",
		       (keepit ? "Keep:  " : "Delete:"), src, sport, dst, dport,
		       repl_src, repl_sport, repl_dst, repl_dport);
	}

	if (keepit) {
		kept++;
		return NFCT_CB_CONTINUE;
	}

	deleted++;
	res = nfct_query(ith, NFCT_Q_DESTROY, ct);
	if (res < 0)
		syslog(LOG_ERR, "Failed flushing conntract rule");

	return NFCT_CB_CONTINUE;
}

static int is_num(char *arg)
{
	while (arg && *arg) {
		if (!isdigit(*arg))
			return 0;

		arg++;
	}

	return 1;
}

int main(int argc, char *argv[])
{
	int i, ret;
	int family = AF_INET;
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	unsigned int seq, portid;

	openlog(__progname, LOG_CONS | LOG_ODELAY, LOG_USER);

	/* Parse port arguments, bail on any argument not being a port number */
	for (i = 1; i < argc; i++) {
		char *arg = argv[i];

		if (!strcmp(arg, "--debug")) {
			debug = 1;
			continue;
		}

		if (!is_num(arg))
			return usage(argc, argv);

		ports[num_ports++] = atoi(arg);

		/* Warn if too many ports are given as argument! */
		if (num_ports == MAX_PORTS && i + 1 < argc) {
			syslog(LOG_WARNING, "Too small internal buffer!"
			       " Not all dports given as argument will be exempt from flushing!");
			break;
		}
	}

	/* Iterate over all local addresses and populate IP list */
	if (debug)
		printf("Iterating over local IP addresses\n");

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_GETADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);
	rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
	rt->rtgen_family = family;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		syslog(LOG_ERR, "Failed opening netlink socket");
		closelog();
		exit(10);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		syslog(LOG_ERR, "Failed binding netlink socket");
		mnl_socket_close(nl);
		closelog();
		exit(10);
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		syslog(LOG_ERR, "Failed sending to netlink socket");
		mnl_socket_close(nl);
		closelog();
		exit(10);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		/* ip_cb() will be run for each interface address */
		ret = mnl_cb_run(buf, ret, seq, portid, ip_cb, NULL);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	if (ret == -1) {
		syslog(LOG_ERR, "Netlink receive error");
		mnl_socket_close(nl);
		closelog();
		exit(10);
	}

	mnl_socket_close(nl);

	/* Sort them to be able to use binary search */
	if (debug)
		printf("Sorting local IP address array\n");

	sort_ip();

	/* Iterate over all conntrack table entries */
	if (debug)
		printf("Iterating over conntrack table entries.\n");

	cth = nfct_open(CONNTRACK, 0);
	if (!cth) {
		syslog(LOG_ERR, "Failed opening primary Netfilter socket");
		closelog();
		exit(10);
	}

	ith = nfct_open(CONNTRACK, 0);
	if (!ith) {
		nfct_close(cth);
		syslog(LOG_ERR, "Failed opening secondary Netfilter socket");
		closelog();
		exit(10);
	}

	/* ct_cb() will be run for each conntrack entry */
	nfct_callback_register(cth, NFCT_T_ALL, ct_cb, NULL);
	ret = nfct_query(cth, NFCT_Q_DUMP, &family);
	if (ret == -1)
		syslog(LOG_ERR, "Failed flushing conntrack rules (NFCT_Q_DUMP)");

	nfct_close(ith);
	nfct_close(cth);

	if (debug)
		printf("Done. Entries kept: %d, deleted: %d\n", kept, deleted);

	if (local_ip) {
		free(local_ip);
		local_ip = NULL;
	}

	closelog();
	exit(0);
}

/**
 * Local Variables:
 *  version-control: t
 *  compile-command: "gcc -g -o unittest -DUNITTEST conntrack-flush.c -lnetfilter_conntrack -lnfnetlink && ./unittest bla"
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
