#include "queue.h"
#include "skel.h"

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
	arp_table = (arp_entry *)malloc(MAX_ARPTABLE_LENGTH * sizeof(arp_entry));
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
void traverse_packets(queue *waiting_packets, arp_header *arp_h) {

	queue *after_removals = queue_create();
	while (!queue_empty(*waiting_packets)) {
		// First packet from queue
		packet *pack = (packet *) queue_deq(*waiting_packets);
		ether_header *ether_h = NULL;
		iphdr *ip_h = NULL;
		ether_h = init_ether_header(pack);
		ip_h = init_ip_header(pack);
		uint32_t dest_addr = ip_h->daddr;
		route_table_entry *fast_route = fastest_route(dest_addr);

		// If it is not the package to be sent to the received mac
		// I don't take it out of the queue
		if (fast_route->next_hop != arp_h->spa) {
			queue_enq(*after_removals, pack);
		} 
		else {
			// Complete the destination mac address for the packet from
			// the queue
			// Complete the destination mac
			memcpy(ether_h->ether_dhost, arp_h->sha, sizeof(arp_h->sha));
			memcpy(ether_h->ether_shost, arp_h->tha, sizeof(arp_h->tha));
			// Send packet
			pack->interface = fast_route->interface;
			send_packet(pack);
		}
	}
	while (!queue_empty(after_removals)) {
        queue_enq(*waiting_packets, queue_deq(*after_removals));
    }
}

iphdr fast_checksum_update(iphdr *ip_h) {

	--ip_h->ttl;
	uint32_t cast_32_bit = (1LL << 32) - 1;
	uint32_t last_sum = ip_h->check;
	uint32_t not_last_sum = (~last_sum + 1);
	uint32_t m_32_before = ((ip_h->ttl + 1) & cast_32_bit);
	uint32_t m_32_after = (ip_h->ttl & cast_32_bit);
	m_32_before = (~m_32_before + 1);
	ip_h->check = (uint16_t *)(~(not_last_sum + m_32_before + m_32_after) + 1);
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

	arp_header arp_h;
	packet *new_packet = (packet *)malloc(sizeof(packet));

	arp_h.htype = htons(ARPHRD_ETHER);
	arp_h.ptype = htons(ETHERTYPE_IP);
	arp_h.op = htons(ARPOP_REQUEST);
	arp_h.hlen = ETH_ALEN;
	arp_h.plen = IPv4_ALEN;
	memcpy(arp_h.sha, ether_h->ether_shost, ETH_ALEN);
	memcpy(arp_h.tha, ether_h->ether_dhost, ETH_ALEN);
	arp_h.spa = inet_addr(get_interface_ip(route.interface));
	arp_h.tpa = route.next_hop;
	memset(new_packet->payload, 0, sizeof(new_packet->payload));
	memcpy(new_packet->payload, ether_h, sizeof(ethhdr));
	memcpy(new_packet->payload + sizeof(ethhdr), &arp_h, sizeof(arp_header));
	new_packet->len = sizeof(arp_header) + sizeof(ethhdr);
	new_packet->interface = route.interface;
	send_packet(new_packet);
}

void arp_reply(packet* pack, arp_header arp_h) {
    ether_header ether_h;
    memset(&ether_h, 0 ,sizeof(ether_header));

    memcpy(ether_h.ether_dhost, arp_h.sha, sizeof(ether_h.ether_dhost));
    get_interface_mac(pack->interface, ether_h.ether_shost);

    ether_h.ether_type = htons(ETHERTYPE_ARP);

	arp_h.op = htons(ARPOP_REPLY);
	memcpy(arp_h.sha, ether_h.ether_shost, ETH_ALEN);
	memcpy(arp_h.tha, ether_h.ether_dhost, ETH_ALEN);
	uint32_t temp = arp_h.tpa;
	arp_h.tpa = arp_h.spa;
	arp_h.spa = temp;
	packet *new_packet = (packet *)malloc(sizeof(packet));
	DIE(new_packet == NULL, "Error : new_packet was not allocated");

	memset(new_packet->payload, 0, sizeof(new_packet->payload));
	memcpy(new_packet->payload, &ether_h, sizeof(ethhdr));
	memcpy(new_packet->payload + sizeof(ethhdr), &arp_h, sizeof(arp_header));
	new_packet->len = sizeof(arp_header) + sizeof(ethhdr);
	new_packet->interface = pack->interface;
	send_packet(new_packet);
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

			if (ip_checksum((uint8_t *)ip_h, sizeof(iphdr)) != 0) {
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

			fast_checksum_update(ip_h);

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
				// Construct a new entry in the arp table
				struct arp_entry *new_arp = malloc(sizeof(struct arp_entry));
				DIE(new_arp == NULL, "Can't alloc a new_entry in arp_table.");

				memcpy(&new_arp->ip, &arp_h->spa, sizeof(arp_h->spa));
				memcpy(&new_arp->mac, &arp_h->sha, sizeof(arp_h->sha));

				arp_table[arp_table_length] = *new_arp;
				arp_table_length++;

				// Dequeue the packet
				traverse_packets(&waiting_packets, arp_h);

				continue;
			}
		}

	}
}
