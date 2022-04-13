#include "queue.h"
#include "skel.h"
#include <stdbool.h>

typedef struct route_table_entry route_table_entry;
typedef struct arp_entry arp_entry;
typedef struct arp_header arp_header;

route_table_entry *rtable;
uint32_t rtable_len = 0;

arp_entry *arp_table;
uint32_t arp_table_len = 0;

int cmpfunc(const void *a, const void *b)
{
	if ((*(struct route_table_entry *)a).prefix != (*(struct route_table_entry *)b).prefix)
	{
		return ((*(struct route_table_entry *)a).prefix - (*(struct route_table_entry *)b).prefix);
	}
	else
	{
		return ((*(struct route_table_entry *)a).mask - (*(struct route_table_entry *)b).mask);
	}
}

struct route_table_entry *get_best_route(uint32_t dest_ip)
{
	int l = 0;
	int r = rtable_len - 1;

	while (l <= r)
	{
		int m = l + (r - l) / 2;

		// Check if I found the prefix
		// printf("Debug : %d %d %d %d\n", m, rtable[m].mask & dest_ip, rtable[m].prefix, rtable_len);
		if ((rtable[m].mask & dest_ip) == rtable[m].prefix)
		{
			// Search the maximum mask
			int ok = 1;
			while (((rtable[m].mask & dest_ip) == rtable[m].prefix) 
					&& (m < (rtable_len - 1)))
			{
				ok = 0;
				m++;
			}
			if (ok == 0)
			{
				return &rtable[m - 1];
			}
			else
			{
				return &rtable[m];
			}
		}
		else
		{
			// If the search prefix is ​​larger than the current one,
			// ignore the left half
			if ((rtable[m].mask & dest_ip) > rtable[m].prefix)
			{
				l = m + 1;
			}
			else
			{
				// Ignore the right half
				r = m - 1;
			}
		}
	}

	// The ip isn't in the route table
	return NULL;
}

void traverse_packets(queue *waiting_packets, uint8_t mac[ETH_ALEN], arp_header *arp_head) {

	while (!queue_empty(*waiting_packets)) {
		// First packet from queue
		packet *to_send = (packet *)peek(*waiting_packets);

		struct iphdr *ip_hdr_q_packet = (struct iphdr *)((*to_send).payload 
										+ sizeof(struct ether_header));
		struct ether_header *eth_hdr;
		eth_hdr = (struct ether_header *)(*to_send).payload;

		struct route_table_entry *best = get_best_route(ip_hdr_q_packet->daddr);

		
		// If it is not the package to be sent to the received mac
		// I don't take it out of the queue
		if (best->next_hop != arp_head->spa)
		{
			break;
		}
		// It's the right package, taking it out of the queue
		else
		{
			to_send = (packet *)queue_deq(*waiting_packets);
		}

		// Complete the destination mac address for the packet from
		// the queue

		// Complete the destination mac
		for (int i = 0; i < ETH_ALEN; i++) {
			eth_hdr->ether_dhost[i] = mac[i];
		}
		for (int i = 0; i < ETH_ALEN; i++) {
			// Update the source mac
			eth_hdr->ether_shost[i] = arp_head->tha[i];
		}

		// Send packet
		to_send->interface = best->interface;
		send_packet(to_send);
	}
}

void push_packet(route_table_entry route, packet m, queue *waiting_packets) {
	m.interface = route.interface;
	queue_enq(*waiting_packets, &m);

	packet *copy_m = malloc(sizeof(m));
	DIE(copy_m == NULL, "Can't alloc a packet.");
	memcpy(copy_m, &m, sizeof(m));

	queue_enq(*waiting_packets, copy_m);
}

void arp_request(route_table_entry route, packet m, queue *waiting_packets) {
	uint32_t daddr = route.next_hop;

	// The ip source is the router's ip
	uint32_t saddr = inet_addr(get_interface_ip(route.interface));
	


	// Construct the ethernet header with my mac as source and
	// broadcast address as destination 
	uint8_t dha[ETH_ALEN];
	memset(dha, 0xFF, ETH_ALEN);

	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "Can't alloc an ether_header.");
	uint8_t mac[ETH_ALEN];
	get_interface_mac(route.interface, mac);
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, mac, ETH_ALEN);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	uint16_t arp_op = htons(ARPOP_REQUEST);

	// Send an ARP_REQUEST
	// send_arp(daddr, saddr, eth_hdr, interface, arp_op);
	struct arp_header arp_hdr;
	packet packet;

	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = arp_op;
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, ETH_ALEN);
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, ETH_ALEN);
	arp_hdr.spa = saddr;
	arp_hdr.tpa = daddr;
	memset(packet.payload, 0, sizeof(packet.payload));
	memcpy(packet.payload, eth_hdr, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_hdr, sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	packet.interface = route.interface;
	send_packet(&packet);
}

void arp_reply(packet* m, struct arp_header arp_head) {
    struct ether_header eth;
    memset(&eth, 0 ,sizeof(struct ether_header));

    memcpy(eth.ether_dhost, arp_head.sha, sizeof(eth.ether_dhost));
    get_interface_mac(m->interface, eth.ether_shost);

    eth.ether_type = htons(ETHERTYPE_ARP);

	arp_head.op = htons(ARPOP_REPLY);
	memcpy(arp_head.sha, eth.ether_shost, ETH_ALEN);
	memcpy(arp_head.tha, eth.ether_dhost, ETH_ALEN);
	uint32_t temp = arp_head.tpa;
	arp_head.tpa = arp_head.spa;
	arp_head.spa = temp;
	packet packet;

	memset(packet.payload, 0, sizeof(packet.payload));
	memcpy(packet.payload, &eth, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_head, sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	packet.interface = m->interface;
	send_packet(&packet);
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc, i;

	init(argc - 2, argv + 2);

	// Create the package queue
	queue waiting_packets = queue_create();

	// Parse the route table
	rtable = (struct route_table_entry *)malloc(100000 * sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], rtable);

	arp_table = malloc(1000 * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "Can't alloc the arp_table.");

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), cmpfunc);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		struct ether_header *eth_head = (struct ether_header*)m.payload;
        struct iphdr *ip_head = (struct iphdr* )(m.payload + sizeof(struct ether_header));
        struct arp_header *arp_head = NULL;
		if (ntohs(eth_head->ether_type) == ETHERTYPE_ARP) {
			arp_head = (struct arp_header *)(m.payload + sizeof(struct ether_header));
		}
		// struct icmphdr *icmp_head = parse_icmp(m.payload);
		if (arp_head != NULL) {
			printf("Check 1");
			if (ntohs(arp_head->op) == ARPOP_REQUEST /*&& inet_addr(get_interface_ip(m.interface)) == arp_head->tpa*/) {
					arp_reply(&m, *arp_head);
					continue;
			}

			if (ntohs(arp_head->op) == ARPOP_REPLY) {
				printf("Ultimate : \n");
				// Extact the ip and the mac receiveds
				uint32_t daddr = arp_head->spa;
				uint8_t mac[ETH_ALEN];
				for (int i = 0; i < ETH_ALEN; i++)
				{
					mac[i] = arp_head->sha[i];
				}

				// Construct a new entry in the arp table
				struct arp_entry *new_cache_entry = malloc(sizeof(struct arp_entry));
				DIE(new_cache_entry == NULL, "Can't alloc a new_entry in arp_table.");

				memcpy(&new_cache_entry->ip, &daddr, sizeof(daddr));
				memcpy(&new_cache_entry->mac, &mac, sizeof(mac));

				// Update the table
				bool found = 0;
				// Add on the last position
				for (i = 0; i < arp_table_len; i++) {
					// Already exists
					if (new_cache_entry->ip == arp_table[i].ip && !strcmp(new_cache_entry->mac, arp_table[i].mac)) {
						found = 1;
						i = arp_table_len;
					}
				}

				// If isn't in the arp table
				// add a new entry
				if (!found) {
						arp_table[arp_table_len] = *new_cache_entry;
						arp_table_len++;
				}

				// Dequeue the packet
				traverse_packets(&waiting_packets, mac, arp_head);

				continue;
			}
		}

		if (ntohs(eth_head->ether_type) == ETHERTYPE_IP) {
			
			printf("Alex");
			if ((inet_addr(get_interface_ip(m.interface))) == ip_head->daddr) {
				continue;
			}

			if (ip_checksum(ip_head, sizeof(struct iphdr)) != 0) {
				continue;
			}

			if (ip_head->ttl <= 1) {
				continue;
			}

			uint32_t dest_addr = ip_head->daddr;
			printf("Cosmin : %d\n", dest_addr);
			route_table_entry *route = get_best_route(dest_addr);

			if (route == NULL) {
				continue;
			}

			--ip_head->ttl;
			ip_head->check = 0;
			ip_head->check = ip_checksum(ip_head, sizeof(struct iphdr));

			arp_entry *cache_arp_entry = NULL;
			for (int i = 0; i < arp_table_len; ++i) {
				if (arp_table[i].ip == ip_head->daddr) {
					cache_arp_entry = &arp_table[i];
				}
			}

			if (cache_arp_entry != NULL) {
			   	get_interface_mac(route, eth_head->ether_shost);
				memcpy(eth_head->ether_dhost, 0, ETH_ALEN);
				memcpy(eth_head->ether_dhost, &cache_arp_entry->mac, sizeof(cache_arp_entry->mac));
				m.interface = route->interface;
				send_packet(&m);
			}
			else {
				arp_request(*route, m, &waiting_packets);
			}

		}




	}
}
