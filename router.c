#include "queue.h"
#include "skel.h"
#include <stdlib.h>

//  Typedef-uri si define-uri folositoare pentru
//flow-ul programului
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

arp_entry *arp_cache_table = NULL;
uint32_t arp_cache_table_length = 0;

/**
 * Functie ce aloca memorie pentru tablea de rutare si apoi citeste informatiile acesteia 
 * din fisierul rtable0.txt
 * */
void init_route_table(char *file) {
	route_table = (struct route_table_entry *)malloc(MAX_RTABLE_LENGTH * sizeof(struct route_table_entry));
	DIE(route_table == NULL, "Error : route_table was not allocated");
	route_table_length = read_rtable(file, route_table);
	return;
}

/**
 * Functie ce aloca memorie pentru tabla de arp pentru cache
 * */
void init_arp_cache_table() {
	arp_cache_table = (arp_entry *)malloc(MAX_ARPTABLE_LENGTH * sizeof(arp_entry));
	DIE(arp_cache_table == NULL, "Error : arp_table was not allocated");
	return;
}

/**
 * Functie de extragere a header-ului de Ethernet din
 * payload-ul unui packet
 * */
ether_header* init_ether_header(packet *pack) {
	return (ether_header *)pack->payload;
}

/**
 * Functie de extragere a header-ului de Ip din
 * payload-ul unui packet (Adresa gasita dupa headerul de Ethernet
 * cand acesta este de tip IPv4)
 * */
iphdr *init_ip_header(packet *pack) {
	return (iphdr *) (pack->payload + sizeof(ether_header));
}

/**
 * Functie de extragere a header-ului de Arp din
 * payload-ul unui packet (Adresa gasita dupa headerul de Ethernet
 * cand acesta este de tip Arp)
 * */
arp_header *init_arp_header(packet *pack) {
	return (arp_header *) (pack->payload + sizeof(ether_header));
}

/**
 * Functie de calculare a celei mai bune rute urmatoare pentru destinatia ip
 * trimisa. Aceasta functie este preluata si modificata din laboratorul 4, 
 * imbunatatind cautarea liniara prin sortarea descrescatoare dupa masca
 * */
struct route_table_entry *fastest_route(uint32_t dest_ip) {
	for (int i = 0; i < route_table_length; ++i) {
		if (route_table[i].prefix == (route_table[i].mask & dest_ip)) {
			return &route_table[i];
		}
	}
	return NULL;
}

/**
 * Functia de compare folosita de qsort (Sorteaza descrescator doua route_table entry
 * dupa masca)
 * */
int compare_func(const void *first, const void *second) {
	route_table_entry *First = (route_table_entry *)first;
	route_table_entry *Second = (route_table_entry *)second;

	return (First->mask) < (Second->mask);
}

/**
 * Dupa ce primim un arp reply, verificam daca next hop-ul unde trebuie 
 * trimise pachetele corespund cu adresa ip a interfetei de pe care am primit raspuns.
 * In caz afirmativ, pachetele sunt trimise la next hop, daca nu, sunt salvate intr-o 
 * a doua coada care apoi este pusa in coada initiala, in acest mod scoatem doar pachetele 
 * dorite din coada initiala
 * */
void traverse_packets(queue *waiting_packets, arp_header *arp_h) {

	// Cea de a doua coada este creata
	queue after_removals = queue_create();
	while (!queue_empty(*waiting_packets)) {
		// Se preia pachetul din fata cozii si se scoate apoi pachetul din coada
		packet *pack = (packet *) queue_deq(*waiting_packets);
		ether_header *ether_h = NULL;
		iphdr *ip_h = NULL;
		// Se extrag headerele de ethernet si ip ale pachetului si se calculeaza 
		// ruta cea mai rapida (interfata unde trebuie trimis pachetul)
		ether_h = init_ether_header(pack);
		ip_h = init_ip_header(pack);
		uint32_t dest_addr = ip_h->daddr;
		route_table_entry *fast_route = fastest_route(dest_addr);
		// Daca pachetul nu trebuie trimis unde indica headerul arp, acesta este introdus 
		// in noua coada
		if (fast_route->next_hop != arp_h->spa) {
			queue_enq(after_removals, pack);
		} 
		else {
			// In caz contrar, se suprascriu adresele de destinatie si sursa de ethernet
			// cu adresele de target si sender din arp
			memcpy(ether_h->ether_shost, arp_h->tha, sizeof(arp_h->tha));
			memcpy(ether_h->ether_dhost, arp_h->sha, sizeof(arp_h->sha));
			// Interfata pachetului trebuie schimbata cu interfata rutei unde ajunge
			pack->interface = fast_route->interface;
			// Pachetul de tip Ipv4 este trimis mai departe spre destinatie
			send_packet(pack);
		}
	}
	// Schimbarea celor doua cozi
	while (!queue_empty(after_removals)) {
        queue_enq(*waiting_packets, queue_deq(after_removals));
    }
}

/**
 * Functie in care am facut update sumei de control folosind formulele 
 * prezentate la link-ul urmator: https://datatracker.ietf.org/doc/html/rfc1624
 * O dificultate a fost intelegerea modului in care rezolvam problema complementului 
 * fata de 1 prin transformarea acestuia in complementul fata de 2. Astfel, in formulele
 * initiale, ~value (complement fata de 1) devine (~value + 1) (complement fata de 2).
 * Astfel suma de control primeste un update eficient
 * */
void fast_checksum_update(iphdr *ip_h) {

	--ip_h->ttl;
	uint32_t cast_32_bit = (1LL << 32) - 1;
	uint32_t last_sum = ip_h->check;
	uint32_t not_last_sum = (~last_sum + 1);
	uint32_t m_32_before = ((ip_h->ttl + 1) & cast_32_bit);
	uint32_t m_32_after = (ip_h->ttl & cast_32_bit);
	m_32_before = (~m_32_before + 1);
	ip_h->check = (uint16_t *)(~(not_last_sum + m_32_before + m_32_after) + 1);
}

/**
 * Functie ce realizeaza un arp request. Aceasta functie este apelata in momentul in care
 * nu se cunoaste adresa mac a interfetei unde trebuie trimis pachetul asa ca dorim sa 
 * facem aceasta cerere catre Broadcast (Pentru a fi vazuta de toata lumea). Astfel, 
 * creem un nou pachet de tip Arp Request care  are headerele si valorile specifice
 * si interfata rutei unde este next hop-ul (In acest fel, cand este primit de 
 * interfata respectiva acest request, ea il identifica si raspunde cu adresa mac)
 * */
void arp_request(route_table_entry route, packet pack, queue waiting_packets) {
	
	// Pachetul ce nu poate fi trimis momentan este adaugat in coada, asteptandu-si
	// arp reply-ul
	packet new_pack;
	memcpy(&new_pack, &pack, sizeof(pack));
	queue_enq(waiting_packets, &new_pack);

	// Se creeaza headerele pentru ethernet, sursa fiind adresa mac a 
	// interfetei next hop-ului iar destinatia fiind Broadcast-ul
	// De asemenea, tipul ethernetului trebuie sa fie ARP
	struct ether_header *ether_h = malloc(sizeof(struct ether_header));
	DIE(ether_h == NULL, "Error : ether_h was not allocated");
	uint8_t mac_addr[ETH_ALEN];
	get_interface_mac(route.interface, mac_addr);
	memcpy(ether_h->ether_shost, mac_addr, ETH_ALEN);
	hwaddr_aton("FF:FF:FF:FF:FF:FF", ether_h->ether_dhost);
	ether_h->ether_type = htons(ETHERTYPE_ARP);

	//	Creem un un nou header arp si un nou pachet in care punem datele 
	// corespunzatoare (Informatii gasite pe wikipedia, ptype, htype, etc) 
	arp_header arp_h;
	packet *new_packet = (packet *)malloc(sizeof(packet));

	arp_h.htype = htons(ARPHRD_ETHER);
	arp_h.ptype = htons(ETHERTYPE_IP);
	arp_h.op = htons(ARPOP_REQUEST);
	arp_h.hlen = ETH_ALEN;
	arp_h.plen = IPv4_ALEN;
	// Adresa mac a senderului este adresa mac a sursei din ethernet header, 
	// respectiv adresa mac a target-ului este adresa mac a destinatiei din ethernet header
	memcpy(arp_h.sha, ether_h->ether_shost, ETH_ALEN);
	memcpy(arp_h.tha, ether_h->ether_dhost, ETH_ALEN);
	// Adresa ip a celui ce va trimite pachetul este adresa ip a sursei 
	// de la care va pleca request-ul, respectiv adresa ip a target-ului este 
	// adresa ip a next hop-ului unde trebuie sa ajungem
	arp_h.spa = inet_addr(get_interface_ip(route.interface));
	arp_h.tpa = route.next_hop;
	// Scriem aceste headere in noul pachet, ii schimbam interfata cu sursa de unde 
	// va pleca pachetul si trimitem pachetul de arp request
	memset(new_packet->payload, 0, sizeof(new_packet->payload));
	memcpy(new_packet->payload, ether_h, sizeof(ethhdr));
	memcpy(new_packet->payload + sizeof(ethhdr), &arp_h, sizeof(arp_header));
	new_packet->len = sizeof(ethhdr) + sizeof(arp_header);
	new_packet->interface = route.interface;
	send_packet(new_packet);
}

/**
 * Functie ce realizeaza un arp reply. Aceasta functie este apelata in momentul in care
 * primim un arp request si urmeaza sa raspundem cu adresa mac a interfetei cautate.
 * Astfel, creem un nou pachet de tip Arp Reply care  are headerele si valorile specifice.
 **/
void arp_reply(packet* pack, arp_header arp_h) {
    ether_header ether_h;
    memset(&ether_h, 0 ,sizeof(ether_header));

	//Adresa mac a sursei de ethernet este adresa mac a pachetului
	//de unde urmam sa facem reply-ul iar adresa destinatie este 
	//luata tot din header-ul de arp si este adresa mac a interfetei 
	//ce a facut request-ul
    get_interface_mac(pack->interface, ether_h.ether_shost);
    memcpy(ether_h.ether_dhost, arp_h.sha, sizeof(ether_h.ether_dhost));

	// Punem tipul de ethernet ca fiind ARP
    ether_h.ether_type = htons(ETHERTYPE_ARP);

	//Punem tipul arp headerului ca fiind de Reply, apoi
	// ca si precedent in Arp Request, copiem datele de 
	// sursa destinatie din header-ul de ethernet in cel de arp
	arp_h.op = htons(ARPOP_REPLY);
	memcpy(arp_h.sha, ether_h.ether_shost, ETH_ALEN);
	memcpy(arp_h.tha, ether_h.ether_dhost, ETH_ALEN);

	// Ip-urile sunt partial corecte, trebuie inversate pentru ca sursa si 
	// destinatia au fost schimbate
	uint32_t temp = arp_h.tpa;
	arp_h.tpa = arp_h.spa;
	arp_h.spa = temp;
	
	packet *new_packet = (packet *)malloc(sizeof(packet));
	DIE(new_packet == NULL, "Error : new_packet was not allocated");
	// Scriem aceste headere in noul pachet, ii schimbam interfata cu sursa de unde 
	// va pleca pachetul si trimitem pachetul de arp reply
	memset(new_packet->payload, 0, sizeof(new_packet->payload));
	memcpy(new_packet->payload, &ether_h, sizeof(ethhdr));
	memcpy(new_packet->payload + sizeof(ethhdr), &arp_h, sizeof(arp_header));
	new_packet->len = sizeof(arp_header) + sizeof(ethhdr);
	new_packet->interface = pack->interface;
	send_packet(new_packet);
}

int main(int argc, char *argv[])
{
	// Linie din cerinta pentru ca stdout sa fie unbuffered
	setvbuf(stdout, NULL, _IONBF, 0);
	packet pack;
	int rc;

	init(argc - 2, argv + 2);

	// Initierea tabelei de rutare
	init_route_table(argv[1]);

	// Am folosit qsort pentru a eficientiza cautarea liniara
	qsort(route_table,route_table_length, sizeof(route_table_entry), compare_func);
	
	// Initializarea tabelei de arp cache
	init_arp_cache_table();

	queue waiting_packets = queue_create();

	while (1) {
		rc = get_packet(&pack);
		DIE(rc < 0, "Error : Getting packet");

		// Extragem headerele pachetului curent primit
		ether_header *ether_h = NULL;
        iphdr *ip_h = NULL;
        arp_header *arp_h = NULL;
		ether_h = init_ether_header(&pack);
		DIE(ether_h == NULL, "Error : ether_h is NULL");
		// Daca tipul de ethernet este ip, extragem header-ul Ip, daca nu, 
		// vom extrage pe cel arp
		if (ntohs(ether_h->ether_type) == ETHERTYPE_IP) {
			ip_h = init_ip_header(&pack);
			DIE(ip_h == NULL, "Error : ip_h is NULL");
		}
		if (ntohs(ether_h->ether_type) == ETHERTYPE_ARP) {
			arp_h = init_arp_header(&pack);
			DIE(arp_h == NULL, "Error : arp_h is NULL");
		}
		
		// Cazul in care avem un pachet IPv4
		if (ip_h != NULL) {
			
			// Daca pachetul este pentru router, acesta trebuie aruncat
			if ((inet_addr(get_interface_ip(pack.interface))) == ip_h->daddr) {
				continue;
			}
			// Daca valoarea sumei de control este diferita de 0, pachetul este din nou aruncat
			if (ip_checksum((uint8_t *)ip_h, sizeof(iphdr)) != 0) {
				continue;
			}
			// Daca ttl-ul a ajuns <= 1, pachetul este aruncat
			if (ip_h->ttl <= 1) {
				continue;
			}
			// Calculam next hop-ul pentru pachetul curent
			uint32_t dest_addr = ip_h->daddr;
			route_table_entry *fast_route = fastest_route(dest_addr);

			// Daca ruta este nula, pachetul trebuie aruncat
			if (fast_route == NULL) {
				continue;
			}
			// In acest moment, pachetul nu este corupt si realizam procesul de
			// forwarding, schimband pentru inceput interfata pachetului in 
			// interfata unde trebuie sa ajunga acesta
			pack.interface = fast_route->interface;

			// Facem update checksum-ului pentru header-ul Ip
			fast_checksum_update(ip_h);

			// Parcurgem cache-ul de adrese mac salvate pentru a verifica daca 
			// adresa mac a destinatiei este deja cunoscuta
			arp_entry *cache_arp = NULL;
			for (int i = 0; i < arp_cache_table_length; ++i) {
				if (arp_cache_table[i].ip == ip_h->daddr) {
					cache_arp = &arp_cache_table[i];
					i = arp_cache_table_length;
				}
			}

			// Daca cunoastem adresa mac a adresei ip a interfetei unde
			// pachetul trebuie sa ajunga, se suprascrie adresa mac a destinatiei din 
			// headerul de ethernet (Care nu era cunoscuta) si se trimite direct pachetul
			if (cache_arp != NULL) {
				memcpy(ether_h->ether_dhost, &cache_arp->mac, ETH_ALEN);
				send_packet(&pack);
			}
			// In caz contrar, se trimite un arp request pentru a afla mac-ul corespunzator
			else {
				arp_request(*fast_route, pack, waiting_packets);
				continue;
			}
		}

		// Cazul in care avem ARP
		if (arp_h != NULL) {
			// In cazul in care primim un arp request, se face reply-ul cu adresa mac a interfetei 
			// dorite
			if (ntohs(arp_h->op) == ARPOP_REQUEST) {
					arp_reply(&pack, *arp_h);
					continue;
			}
			// In caz contrar, am primit un reply si tocmai am aflat adresa mac dorita de 
			// unele pachete din coada. Astfel, creem un nou arp cache pe care il adaugam in 
			// lista de mac-uri cunoscute, traversam pachetele existente si le trimitem pe cele
			// ce asteptau adresa mac corespunzatoare
			if (ntohs(arp_h->op) == ARPOP_REPLY) {
				struct arp_entry *new_arp = malloc(sizeof(struct arp_entry));
				DIE(new_arp == NULL, "Can't alloc a new_entry in arp_table.");

				memcpy(&new_arp->ip, &arp_h->spa, sizeof(arp_h->spa));
				memcpy(&new_arp->mac, &arp_h->sha, sizeof(arp_h->sha));
				traverse_packets(&waiting_packets, arp_h);
				arp_cache_table[arp_cache_table_length] = *new_arp;
				arp_cache_table_length++;

				continue;
			}
		}
	}
}
