// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// netgraph-agent's connection events: which process opened each connection,
// seen in the kernel as it happens, so a connection that lasts a few
// milliseconds, or a program that runs for one, is still named.
//
// It reads; it never changes a packet, a socket or a decision. Each event is
// a connection's protocol, addresses and ports (an ICMP echo's identifier as
// its local port), the socket's inode, and the process: PID, parent, start
// time, user and command name. No payload is read beyond a UDP header
// or the ICMP header a program sends. Only sockets in the network
// namespace the agent names are reported.
//
// Build with `make bpf` (clang, in a container); the objects are checked in,
// so building the agent needs no clang.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// The few kernel types read, by name: CO-RE finds each field in the running
// kernel's BTF, wherever that kernel puts it.
struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
} __attribute__((preserve_access_index));

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
	struct ns_common ns;
} __attribute__((preserve_access_index));

typedef struct {
	struct net *net;
} possible_net_t;

struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct socket;

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
	struct socket *sk_socket;
} __attribute__((preserve_access_index));

struct socket {
	struct sock *sk;
	struct file *file;
} __attribute__((preserve_access_index));

struct sk_buff {
	struct sock *sk;
	unsigned char *head;
	__u16 transport_header;
	__u16 network_header;
} __attribute__((preserve_access_index));

struct task_struct {
	int tgid;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
	__u64 start_boottime;
} __attribute__((preserve_access_index));

struct iovec {
	void *iov_base;
} __attribute__((preserve_access_index));

enum iter_type { ITER_UBUF, ITER_IOVEC };

struct iov_iter {
	__u8 iter_type;
	union {
		struct {
			union {
				const struct iovec *__iov;
				void *ubuf;
			};
		};
	};
} __attribute__((preserve_access_index));

struct msghdr {
	void *msg_name;
	struct iov_iter msg_iter;
} __attribute__((preserve_access_index));

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

enum kind { KIND_CONNECT = 1, KIND_ACCEPT = 2, KIND_SEND = 3 };

struct event {
	__u64 start; // the process's start, ns after boot (as /proc/<pid>/stat counts it)
	__u64 ino;   // the socket's inode, as /proc/<pid>/fd names it
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u16 family;
	__u8 proto;
	__u8 kind;
	__u16 sport; // host order; an ICMP echo's identifier
	__u16 dport;
	__u8 saddr[16]; // IPv4 in the first four bytes
	__u8 daddr[16];
	char comm[16];
};

// Remember sends for a while, so a busy UDP flow or a long ping is one event
// every few seconds, not one per packet.
struct send_key {
	__u32 pid;
	__u16 sport;
	__u16 dport;
	__u8 daddr[16];
	__u8 proto;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct send_key);
	__type(value, __u64);
} sends SEC(".maps");

// config[0] is the network namespace's inode to report (0: every one).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} config SEC(".maps");

#define SEND_EVERY_NS (5ULL * 1000 * 1000 * 1000)

static __always_inline int wanted_net(struct net *net)
{
	__u32 zero = 0;
	__u32 *want = bpf_map_lookup_elem(&config, &zero);
	if (!want || *want == 0)
		return 1;
	return BPF_CORE_READ(net, ns.inum) == *want;
}

static __always_inline void fill_task(struct event *e)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	// The process's start, not this thread's: /proc/<pid>/stat's.
	e->start = BPF_CORE_READ(t, group_leader, start_boottime);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
}

static __always_inline __u64 sock_ino(struct socket *so)
{
	return BPF_CORE_READ(so, file, f_inode, i_ino);
}

// read_addrs copies a socket's own addresses (the source is zero until bound).
static __always_inline void read_addrs(struct sock *sk, __u16 family, __u8 *saddr, __u8 *daddr)
{
	if (family == AF_INET) {
		bpf_core_read(saddr, 4, &sk->__sk_common.skc_rcv_saddr);
		bpf_core_read(daddr, 4, &sk->__sk_common.skc_daddr);
	} else {
		bpf_core_read(saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_core_read(daddr, 16, &sk->__sk_common.skc_v6_daddr);
	}
}

// emit_sock reports a TCP socket's connection, from its own fields.
static __always_inline void emit_sock(struct sock *sk, struct socket *so, __u8 kind)
{
	if (!sk || !wanted_net(BPF_CORE_READ(sk, __sk_common.skc_net.net)))
		return;
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	fill_task(e);
	e->kind = kind;
	e->family = family;
	e->proto = IPPROTO_TCP;
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	read_addrs(sk, family, e->saddr, e->daddr);
	if (!so)
		so = BPF_CORE_READ(sk, sk_socket);
	if (so)
		e->ino = sock_ino(so);
	bpf_ringbuf_submit(e, 0);
}

// An outbound TCP connection: its source address and port are chosen by now.
SEC("fentry/tcp_connect")
int BPF_PROG(on_connect, struct sock *sk)
{
	emit_sock(sk, 0, KIND_CONNECT);
	return 0;
}

// An accepted TCP connection, in the process that accepted it. Not at
// inet_accept, which a kernel may inline into the accept syscall (Go's
// accepts never reach it as a function), but at the protocol's accept, as
// it returns the new socket: its arguments differ between kernels, its
// return value doesn't. The socket has no file yet, so no inode: the agent
// finds it by its addresses.
SEC("fexit/inet_csk_accept")
int BPF_PROG(on_accept, struct sock *sk)
{
	__u64 ret = 0;
	if (bpf_get_func_ret(ctx, &ret) || !ret)
		return 0;
	emit_sock((struct sock *)ret, 0, KIND_ACCEPT);
	return 0;
}

// recent reports whether this process sent on this tuple in the last few
// seconds, and remembers that it did now.
static __always_inline int recent(struct send_key *k)
{
	__u64 now = bpf_ktime_get_ns();
	__u64 *last = bpf_map_lookup_elem(&sends, k);
	if (last && now - *last < SEND_EVERY_NS)
		return 1;
	bpf_map_update_elem(&sends, k, &now, BPF_ANY);
	return 0;
}

static __always_inline void emit_send(struct sock *sk, struct send_key *k, __u16 family, __u8 *saddr)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	fill_task(e);
	e->kind = KIND_SEND;
	e->family = family;
	e->proto = k->proto;
	e->sport = k->sport;
	e->dport = k->dport;
	__builtin_memcpy(e->saddr, saddr, 16);
	__builtin_memcpy(e->daddr, k->daddr, 16);
	struct socket *so = BPF_CORE_READ(sk, sk_socket);
	if (so)
		e->ino = sock_ino(so);
	bpf_ringbuf_submit(e, 0);
}

// on_udp reports a UDP datagram leaving a socket, with the addresses and
// ports as they go on the wire: an unbound socket has no source address
// until the route chooses one.
static __always_inline void on_udp(struct sk_buff *skb, __u16 family)
{
	struct sock *sk = BPF_CORE_READ(skb, sk);
	if (!sk || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_UDP || !wanted_net(BPF_CORE_READ(sk, __sk_common.skc_net.net)))
		return;
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 nh = BPF_CORE_READ(skb, network_header);
	__u16 th = BPF_CORE_READ(skb, transport_header);
	if (!head || nh == 0xffff || th == 0xffff)
		return;
	__u8 l4[4];
	if (bpf_probe_read_kernel(l4, sizeof(l4), head + th))
		return;
	struct send_key k = {};
	k.pid = bpf_get_current_pid_tgid() >> 32;
	k.proto = IPPROTO_UDP;
	k.sport = ((__u16)l4[0] << 8) | l4[1];
	k.dport = ((__u16)l4[2] << 8) | l4[3];
	__u8 saddr[16] = {};
	if (family == AF_INET) {
		__u8 ip[20];
		if (bpf_probe_read_kernel(ip, sizeof(ip), head + nh))
			return;
		__builtin_memcpy(saddr, ip + 12, 4);
		__builtin_memcpy(k.daddr, ip + 16, 4);
	} else {
		__u8 ip[40];
		if (bpf_probe_read_kernel(ip, sizeof(ip), head + nh))
			return;
		__builtin_memcpy(saddr, ip + 8, 16);
		__builtin_memcpy(k.daddr, ip + 24, 16);
	}
	if (recent(&k))
		return;
	emit_send(sk, &k, family, saddr);
}

// on_echo reports an ICMP echo request a program sends, on a ping socket
// (whose port is the echo identifier the kernel writes) or a raw one (whose
// program wrote the identifier itself). The source address is the socket's
// if it is bound, else zero: the agent asks the routing table.
static __always_inline void on_echo(struct sock *sk, struct msghdr *msg, __u16 family, int raw)
{
	__u16 proto = BPF_CORE_READ(sk, sk_protocol);
	if ((family == AF_INET && proto != IPPROTO_ICMP) || (family == AF_INET6 && proto != IPPROTO_ICMPV6))
		return;
	if (!wanted_net(BPF_CORE_READ(sk, __sk_common.skc_net.net)))
		return;
	// The ICMP header the program wrote, from its own buffer.
	void *buf = 0;
	__u8 it = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (it == bpf_core_enum_value(enum iter_type, ITER_UBUF))
		buf = BPF_CORE_READ(msg, msg_iter.ubuf);
	else if (it == bpf_core_enum_value(enum iter_type, ITER_IOVEC))
		buf = BPF_CORE_READ(msg, msg_iter.__iov, iov_base);
	__u8 icmp[8];
	if (!buf || bpf_probe_read_user(icmp, sizeof(icmp), buf))
		return;
	if (icmp[0] != (family == AF_INET ? 8 : 128))
		return;
	struct send_key k = {};
	k.pid = bpf_get_current_pid_tgid() >> 32;
	k.proto = proto;
	k.sport = raw ? (((__u16)icmp[4] << 8) | icmp[5]) : BPF_CORE_READ(sk, __sk_common.skc_num);
	__u8 saddr[16] = {};
	read_addrs(sk, family, saddr, k.daddr);
	// Where it goes: the address sendto named, else the connected peer's.
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		__u16 af = 0;
		bpf_probe_read_kernel(&af, sizeof(af), name);
		if (af != family)
			return;
		if (family == AF_INET)
			bpf_probe_read_kernel(k.daddr, 4, name + 4);
		else
			bpf_probe_read_kernel(k.daddr, 16, name + 8);
	}
	if (recent(&k))
		return;
	emit_send(sk, &k, family, saddr);
}

SEC("fentry/ping_v4_sendmsg")
int BPF_PROG(on_ping4, struct sock *sk, struct msghdr *msg)
{
	on_echo(sk, msg, AF_INET, 0);
	return 0;
}

SEC("fentry/ping_v6_sendmsg")
int BPF_PROG(on_ping6, struct sock *sk, struct msghdr *msg)
{
	on_echo(sk, msg, AF_INET6, 0);
	return 0;
}

SEC("fentry/raw_sendmsg")
int BPF_PROG(on_raw4, struct sock *sk, struct msghdr *msg)
{
	on_echo(sk, msg, AF_INET, 1);
	return 0;
}

SEC("fentry/rawv6_sendmsg")
int BPF_PROG(on_raw6, struct sock *sk, struct msghdr *msg)
{
	on_echo(sk, msg, AF_INET6, 1);
	return 0;
}

// UDP reaches these from udp.c; ping and raw sockets' sends may have them
// inlined, which is why echoes are taken at their sendmsg.
SEC("fentry/ip_send_skb")
int BPF_PROG(on_udp4, struct net *net, struct sk_buff *skb)
{
	on_udp(skb, AF_INET);
	return 0;
}

SEC("fentry/ip6_send_skb")
int BPF_PROG(on_udp6, struct sk_buff *skb)
{
	on_udp(skb, AF_INET6);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
