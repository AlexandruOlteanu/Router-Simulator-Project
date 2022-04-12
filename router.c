#include "queue.h"
#include "skel.h"

struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;

void update_arp_table(struct arp_entry new_entry)
{
	int i;
	// Add on the last position
	for (i = 0; i < arp_table_len; i++)
	{
		// Already exists
		if (new_entry.ip == arp_table[i].ip &&
			new_entry.mac == arp_table[i].mac)
		{
			break;
		}
	}

	// If isn't in the arp table
	// add a new entry
	if (i == arp_table_len)
	{
		arp_table[arp_table_len] = new_entry;
		arp_table_len++;
	}
}

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
	int r = rtable_size - 1;

	while (l <= r)
	{
		int m = l + (r - l) / 2;

		// Check if I found the prefix
		if ((rtable[m].mask & dest_ip) == rtable[m].prefix)
		{
			// Search the maximum mask
			int ok = 1;
			while (((rtable[m].mask & dest_ip) == rtable[m].prefix) 
					&& (m < (rtable_size - 1)))
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

void complete_mac_ether_hdr(struct ether_header *eth_hdr,
							uint8_t mac[ETH_ALEN],
							struct arp_header *arp_hdr)
{
	int i;
	// Complete the destination mac
	for (i = 0; i < ETH_ALEN; i++)
	{
		eth_hdr->ether_dhost[i] = mac[i];
	}
	for (i = 0; i < ETH_ALEN; i++)
	{
		// Update the source mac
		eth_hdr->ether_shost[i] = arp_hdr->tha[i];
	}
}

void dequeue_packets(queue *q_packets, uint8_t mac[ETH_ALEN],
					 struct arp_header *arp_hdr)
{
	// Dequeue the packets
	while (!queue_empty(*q_packets))
	{
		// First packet from queue
		packet *to_send = (packet *)peek(*q_packets);

		struct iphdr *ip_hdr_q_packet = (struct iphdr *)((*to_send).payload 
										+ sizeof(struct ether_header));
		struct ether_header *eth_hdr;
		eth_hdr = (struct ether_header *)(*to_send).payload;

		struct route_table_entry *best = get_best_route(ip_hdr_q_packet->daddr);

		
		// If it is not the package to be sent to the received mac
		// I don't take it out of the queue
		if (best->next_hop != arp_hdr->spa)
		{
			break;
		}
		// It's the right package, taking it out of the queue
		else
		{
			to_send = (packet *)queue_deq(*q_packets);
		}

		// Complete the destination mac address for the packet from
		// the queue
		complete_mac_ether_hdr(eth_hdr, mac, arp_hdr);

		// Send packet
		to_send->interface = best->interface;
		printf("Maria %d\n", to_send->interface);
		send_packet(to_send);
	}
}

void arp_reply(packet* pack, struct arp_header *recv_packet)
{
    struct in_addr ip_addr;
    struct ether_header eth;
    memset(&eth, 0 ,sizeof(struct ether_header));

    memcpy(eth.ether_dhost, recv_packet->sha, sizeof(eth.ether_dhost));
    get_interface_mac(pack->interface, eth.ether_shost);

    eth.ether_type = htons(ETHERTYPE_ARP);

    ip_addr.s_addr = recv_packet->tpa;
    inet_aton(get_interface_ip(pack->interface), &ip_addr);
	struct arp_header arp_hdr;
	packet packet;

	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = htons(ARPOP_REPLY);
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	memcpy(arp_hdr.sha, eth.ether_shost, 6);
	memcpy(arp_hdr.tha, eth.ether_dhost, 6);
	arp_hdr.spa = recv_packet->tpa;
	arp_hdr.tpa = recv_packet->spa;
	memset(packet.payload, 0, 1600);
	memcpy(packet.payload, &eth, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_hdr, sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	packet.interface = pack->interface;
	send_packet(&packet);
}

void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op)
{
	struct arp_header arp_hdr;
	packet packet;

	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = arp_op;
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, 6);
	arp_hdr.spa = saddr;
	arp_hdr.tpa = daddr;
	memset(packet.payload, 0, 1600);
	memcpy(packet.payload, eth_hdr, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_hdr, sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	packet.interface = interface;
	send_packet(&packet);
}

void send_arp_reply(struct arp_header *recv_packet, int interface)
{
    struct in_addr ip_addr;
    struct ether_header eth;
    memset(&eth, 0 ,sizeof(struct ether_header));

    memcpy(eth.ether_dhost, recv_packet->sha, sizeof(eth.ether_dhost));
    get_interface_mac(interface, eth.ether_shost);

    eth.ether_type = htons(ETHERTYPE_ARP);

    ip_addr.s_addr = recv_packet->tpa;
    inet_aton(get_interface_ip(interface), &ip_addr);
    send_arp(recv_packet->spa, recv_packet->tpa, &eth, interface, htons(ARPOP_REPLY));
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc, i;

	init(argc - 2, argv + 2);

	// Create the package queue
	queue q_packets = queue_create();

	// Parse the route table
	rtable = (struct route_table_entry *)malloc(100000 * sizeof(struct route_table_entry));
	read_rtable(argv[1], rtable);

	arp_table = malloc(1000 * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "Can't alloc the arp_table.");

	qsort(rtable, rtable_size, sizeof(struct route_table_entry), cmpfunc);

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
			if (ntohs(arp_head->op) == ARPOP_REQUEST && inet_addr(get_interface_ip(m.interface)) == arp_head->tpa) {
					arp_reply(&m, arp_head);
					continue;
			}

			if (ntohs(arp_head->op) == ARPOP_REPLY) {
				// Extact the ip and the mac receiveds
				uint32_t daddr = arp_head->spa;
				uint8_t mac[ETH_ALEN];
				for (int i = 0; i < ETH_ALEN; i++)
				{
					mac[i] = arp_head->sha[i];
				}

				// Construct a new entry in the arp table
				struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
				DIE(new_entry == NULL, "Can't alloc a new_entry in arp_table.");

				memcpy(&new_entry->ip, &daddr, sizeof(daddr));
				memcpy(&new_entry->mac, &mac, sizeof(mac));

				// Update the table
				update_arp_table(*new_entry);

				// Dequeue the packet
				dequeue_packets(&q_packets, mac, arp_head);
				continue;
			}


		}
	}
}
