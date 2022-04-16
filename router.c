#include "queue.h"
#include "skel.h"
#include <stdbool.h>

typedef struct route_table_entry route_table_entry;
typedef struct arp_entry arp_entry;
typedef struct arp_header arp_header;
typedef struct ether_header ether_header;
typedef struct iphdr iphdr;
typedef struct ethhdr ethhdr;
#define MAX_RTABLE_LENGTH 100000
#define MAX_ARPTABLE_LENGTH 100
#define IPv4_ALEN 4

route_table_entry *route_table = NULL;
uint32_t route_table_length = 0;

arp_entry *arp_table = NULL;
uint32_t arp_table_length = 0;

void init_route_table(char *file) {
	route_table = (struct route_table_entry *)malloc(MAX_RTABLE_LENGTH * sizeof(struct route_table_entry));
	DIE(route_table == NULL, "Error : route_table was not allocated");
	route_table_length = read_rtable(file, route_table);
	return;
}

void init_arp_table() {
	arp_table = malloc(MAX_ARPTABLE_LENGTH * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "Error : arp_table was not allocated");
	return;
}

ether_header* init_ether_header(packet *pack) {
	return (ether_header *)pack->payload;
}

iphdr *init_ip_header(packet *pack) {
	return (iphdr *) (pack->payload + sizeof(ether_header));
}

arp_header *init_arp_header(packet *pack) {
	return (arp_header *) (pack->payload + sizeof(ether_header));
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

struct route_table_entry *fastest_route(uint32_t dest_ip) {
	route_table_entry *bc = NULL;
	for (int i = 0; i < route_table_length; ++i) {
		if ((route_table[i].mask & dest_ip) == route_table[i].prefix) {
			if (bc == NULL) {
				bc = &route_table[i];
			}
			else if(ntohl(bc->mask) < ntohl(route_table[i].mask)) {
				bc = &route_table[i];
			} 
		}
	}
	return bc;
}

void traverse_packets(queue *waiting_packets, uint8_t mac[ETH_ALEN], arp_header *arp_head) {

	while (!queue_empty(*waiting_packets)) {
		// First packet from queue
		packet *to_send = (packet *)peek(*waiting_packets);

		struct iphdr *ip_hdr_q_packet = (struct iphdr *)((*to_send).payload 
										+ sizeof(struct ether_header));
		struct ether_header *eth_hdr;
		eth_hdr = (struct ether_header *)(*to_send).payload;

		struct route_table_entry *best = fastest_route(ip_hdr_q_packet->daddr);

		
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

void arp_request(route_table_entry route, packet m, queue *waiting_packets) {
	
	// Construct the ethernet header with my mac as source and
	// broadcast address as destination 

	struct ether_header *ether_h = malloc(sizeof(struct ether_header));
	DIE(ether_h == NULL, "Error : ether_h was not allocated");
	uint8_t mac_addr[ETH_ALEN];
	get_interface_mac(route.interface, mac_addr);
	memcpy(ether_h->ether_shost, mac_addr, ETH_ALEN);
	hwaddr_aton("FF:FF:FF:FF:FF", ether_h->ether_dhost);
	ether_h->ether_type = htons(ETHERTYPE_ARP);

	struct arp_header arp_hdr;
	packet packet;

	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(ETHERTYPE_IP);
	arp_hdr.op = htons(ARPOP_REQUEST);
	arp_hdr.hlen = ETH_ALEN;
	arp_hdr.plen = IPv4_ALEN;
	memcpy(arp_hdr.sha, ether_h->ether_shost, ETH_ALEN);
	memcpy(arp_hdr.tha, ether_h->ether_dhost, ETH_ALEN);
	arp_hdr.spa = inet_addr(get_interface_ip(route.interface));
	arp_hdr.tpa = route.next_hop;
	memset(packet.payload, NULL, sizeof(packet.payload));
	memcpy(packet.payload, ether_h, sizeof(ethhdr));
	memcpy(packet.payload + sizeof(ethhdr), &arp_hdr, sizeof(arp_header));
	packet.len = sizeof(arp_header) + sizeof(ethhdr);
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
	packet pack;
	int rc;

	init(argc - 2, argv + 2);

	// Parse the route table
	init_route_table(argv[1]);

	qsort(route_table, route_table_length, sizeof(struct route_table_entry), cmpfunc);

	init_arp_table();

	// Create the package queue
	queue waiting_packets = queue_create();

	while (1) {
		rc = get_packet(&pack);
		DIE(rc < 0, "Error : Getting packet");

		ether_header *ether_h = NULL;
        iphdr *ip_h = NULL;
        arp_header *arp_h = NULL;
		ether_h = init_ether_header(&pack);
		DIE(ether_h == NULL, "Error : ether_h is NULL");
		if (ntohs(ether_h->ether_type) == ETHERTYPE_IP) {
			ip_h = init_ip_header(&pack);
			DIE(ip_h == NULL, "Error : ip_h is NULL");
		}
		if (ntohs(ether_h->ether_type) == ETHERTYPE_ARP) {
			arp_h = init_arp_header(&pack);
			DIE(arp_h == NULL, "Error : arp_h is NULL");
		}
		
		if (ip_h != NULL) {
			
			if ((inet_addr(get_interface_ip(pack.interface))) == ip_h->daddr) {
				continue;
			}

			if (ip_checksum(ip_h, sizeof(struct iphdr)) != 0) {
				continue;
			}

			if (ip_h->ttl <= 1) {
				continue;
			}

			uint32_t dest_addr = ip_h->daddr;
			route_table_entry *fast_route = fastest_route(dest_addr);

			if (fast_route == NULL) {
				continue;
			}
			pack.interface = fast_route->interface;

			--ip_h->ttl;
			ip_h->check = 0;
			ip_h->check = ip_checksum(ip_h, sizeof(struct iphdr));

			arp_entry *cache_arp = NULL;
			for (int i = 0; i < arp_table_length; ++i) {
				if (arp_table[i].ip == ip_h->daddr) {
					cache_arp = &arp_table[i];
					i = arp_table_length;
				}
			}

			if (cache_arp != NULL) {
				memcpy(ether_h->ether_dhost, &cache_arp->mac, ETH_ALEN);
				send_packet(&pack);
			}
			else {

				// I put the package in the queue and 
				// update the interface
				packet new_pack;
				memcpy(&new_pack, &pack, sizeof(pack));
				queue_enq(waiting_packets, &new_pack);
				arp_request(*fast_route, pack, &waiting_packets);
				continue;
			}
		}

		if (arp_h != NULL) {
			if (ntohs(arp_h->op) == ARPOP_REQUEST) {
					arp_reply(&pack, *arp_h);
					continue;
			}

			if (ntohs(arp_h->op) == ARPOP_REPLY) {
				//Extact the ip and the mac receiveds
				uint32_t daddr = arp_h->spa;
				uint8_t mac[ETH_ALEN];
				for (int i = 0; i < ETH_ALEN; i++)
				{
					mac[i] = arp_h->sha[i];
				}

				// Construct a new entry in the arp table
				struct arp_entry *new_cache_entry = malloc(sizeof(struct arp_entry));
				DIE(new_cache_entry == NULL, "Can't alloc a new_entry in arp_table.");

				memcpy(&new_cache_entry->ip, &daddr, sizeof(daddr));
				memcpy(&new_cache_entry->mac, &mac, sizeof(mac));

				// Update the table
				bool found = 0;
				// Add on the last position
				for (int i = 0; i < arp_table_length; i++) {
					// Already exists
					if (new_cache_entry->ip == arp_table[i].ip && !strcmp(new_cache_entry->mac, arp_table[i].mac)) {
						found = 1;
						i = arp_table_length;
					}
				}

				// If isn't in the arp table
				// add a new entry
				if (!found) {
						arp_table[arp_table_length] = *new_cache_entry;
						arp_table_length++;
				}

				// Dequeue the packet
				traverse_packets(&waiting_packets, mac, arp_h);

				continue;
			}
		}

	}
}
