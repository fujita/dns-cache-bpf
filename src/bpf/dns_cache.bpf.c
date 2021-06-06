/*
 * Copyright (C) 2021 The dns-cache-bpf Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_ALEN 6

#define MAX_DOMAIN_LENGTH 64
#define NUM_CACHE 8192

struct header {
	__u16 trans_id;
	__u8 flags0;
	__u8 flags1;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
} __attribute__((packed));

struct domain_info {
	__u16 type;
	__u16 class;
} __attribute__((packed));

struct answer {
	__u16 pointer;
	__u16 type;
	__u16 class;
	__u32 ttl;
	__u16 datalen;
	__u32 address;
} __attribute__((packed));

struct record {
	__u32 address;
	__u32 ttl;
};

#define CACHE_HIT_IDX 0
#define CACHE_MISS_IDX 1

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 2);
} statsmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, MAX_DOMAIN_LENGTH);
	__uint(value_size, sizeof(struct record));
	__uint(max_entries, NUM_CACHE);
} recordmap SEC(".maps");

static inline u16 compute_ip_checksum(struct iphdr *ip)
{
	u32 csum = 0;
	u16 *next_ip_u16 = (u16 *)ip;

	ip->check = 0;

#pragma clang loop unroll(full)
	for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
		csum += *next_ip_u16++;
	}

	return ~((csum & 0xffff) + (csum >> 16));
}

SEC("xdp")
int xdp_dns_handler(struct xdp_md *ctx)
{
	int i;
	struct record rec;
	__builtin_memset(&rec, 0, sizeof(rec));
	__u8 name[MAX_DOMAIN_LENGTH];
	__builtin_memset(&name, 0, sizeof(name));
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	struct answer *ans;

	if (ip + 1 > data_end)
		return XDP_PASS;

	if (ip->protocol != IPPROTO_UDP) {
		return XDP_PASS;
	}

	struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
	if (udp + 1 > data_end) {
		return XDP_PASS;
	}

	if (udp->dest != bpf_ntohs(53) && udp->source != bpf_ntohs(53)) {
		return XDP_PASS;
	}

	struct header *h = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
	if (h + 1 > data_end) {
		return XDP_PASS;
	}
	u16 payload_len = data_end - (void *)h;
	u16 qdcount = bpf_ntohs(h->qdcount);
	u16 ancount = bpf_ntohs(h->ancount);
	u16 nscount = bpf_ntohs(h->nscount);
	u16 arcount = bpf_ntohs(h->arcount);

	if (qdcount != 1) {
		return XDP_PASS;
	}

	u16 offset = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*h);
	u8 *d = data + offset;

	for (i = 0; i < MAX_DOMAIN_LENGTH; i++) {
		if (d + 1 > data_end) {
			return XDP_PASS;
		}
		if (*d == 0) {
			break;
		}
		d = (void *)d + (*d + 1);
	}
	u16 name_len = (void *)d - (data + sizeof(*eth) + sizeof(*ip) +
				    sizeof(*udp) + sizeof(*h));
	if (name_len > sizeof(name)) {
		return XDP_PASS;
	}
	u16 name_offset = offset;
	u8 *p;
	for (i = 0; i < sizeof(name); i++) {
		if (data + name_offset + sizeof(*p) > data_end) {
			return XDP_PASS;
		}
		p = data + name_offset;
		name[i] = *p;
		name_offset += sizeof(*p);
		if (i > name_len) {
			break;
		}
	}

	struct domain_info *info = d + 1;
	if (info + 1 > data_end) {
		return XDP_PASS;
	}
	if (bpf_ntohs(info->class) != 1 || bpf_ntohs(info->type) != 1) {
		return XDP_PASS;
	}
	ans = (void *)info + sizeof(*info);

	if (udp->dest == bpf_ntohs(53)) {
		__u64 *v;
		struct record *r = bpf_map_lookup_elem(&recordmap, &name);
		if (!r) {
			u32 key = CACHE_MISS_IDX;
			v = bpf_map_lookup_elem(&statsmap, &key);
			if (v)
				__sync_fetch_and_add(v, 1);
			return XDP_PASS;
		}
		u32 key = CACHE_HIT_IDX;
		v = bpf_map_lookup_elem(&statsmap, &key);
		if (v)
			__sync_fetch_and_add(v, 1);

		rec.address = r->address;
		rec.ttl = r->ttl;

		u16 old_packet_len = data_end - data;
		u16 new_packet_len =
			sizeof(struct ethhdr) + sizeof(struct iphdr) +
			sizeof(struct udphdr) + sizeof(struct header) +
			name_len + 1 + sizeof(struct domain_info) +
			sizeof(struct answer);

		unsigned char tmp_mac[ETH_ALEN];
		memcpy(tmp_mac, eth->h_source, ETH_ALEN);
		memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
		memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

		__be32 tmp_ip = ip->saddr;
		ip->saddr = ip->daddr;
		ip->daddr = tmp_ip;
		ip->check = 0;
		ip->tot_len = bpf_htons(new_packet_len - sizeof(struct ethhdr));

		__be16 tmp_port = udp->source;
		udp->source = udp->dest;
		udp->dest = tmp_port;
		udp->check = 0;
		udp->len = bpf_htons(new_packet_len - (sizeof(struct ethhdr) +
						       sizeof(struct iphdr)));

		ip->check = compute_ip_checksum(ip);

		h->flags0 = 0x81;
		h->flags1 = 0x82;
		h->qdcount = bpf_htons(1);
		h->ancount = bpf_htons(1);
		h->nscount = bpf_htons(0);
		h->arcount = bpf_htons(0);

		if (ans + 1 > data_end) {
			return XDP_PASS;
		}
		ans->pointer = bpf_htons(0xc00c);
		ans->type = bpf_htons(1);
		ans->class = bpf_htons(1);
		ans->ttl = rec.ttl;
		ans->datalen = bpf_htons(4);
		ans->address = rec.address;

		int delta = new_packet_len - old_packet_len;
		int err = bpf_xdp_adjust_tail(ctx, delta);
		if (err != 0) {
			return XDP_PASS;
		}
		return XDP_TX;
	}
	// answer
	if (ancount != 1) {
		return XDP_PASS;
	}

	if (ans + 1 > data_end) {
		return XDP_PASS;
	}

	if (bpf_ntohs(ans->pointer) != 0xc00c) {
		return XDP_PASS;
	}

	rec.address = ans->address;
	rec.ttl = ans->ttl;
	bpf_map_update_elem(&recordmap, &name, &rec, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
