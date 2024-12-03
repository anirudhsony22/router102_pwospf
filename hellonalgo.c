// #include <stdio.h>
// #include <string.h>

// #define MAX_DB_ENTRIES 100
// #define MAX_RTABLE_ENTRIES 100
// #define VALID 1
// #define INVALID 0
// #define UNVISITED 0
// #define VISITED 1

// typedef struct {
//     char source_rid[16];     // Source Router ID
//     char subnet[16];         // Subnet address
//     char mask[16];           // Subnet mask
//     char neighbour_rid[16];  // Neighbour Router ID (Subnet of link)
//     int valid;               // VALID or INVALID
//     int color_visited;       // UNVISITED or VISITED
// } db_struct;

// typedef struct {
//     char destination[16];    // Destination subnet
//     char mask[16];           // Destination mask
//     char next_hop[16];       // Next hop subnet
// } rtable_entry;

// /* Function to reset color_visited in the database */
// void reset_color_visited(db_struct *db, int db_size) {
//     for (int i = 0; i < db_size; i++) {
//         db[i].color_visited = UNVISITED;
//     }
// }

// /* Function to build the routing table using BFS */
// void build_routing_table(db_struct *db, int db_size, const char *self_rid, rtable_entry *rtable, int *rtable_size) {
//     int queue[MAX_DB_ENTRIES];
//     int front = 0, rear = 0;
//     reset_color_visited(db, db_size);
//     /* Enqueue entries where Source RID == self_rid and Valid */
//     for (int i = 0; i < db_size; i++) {
//         if (db[i].valid == VALID && strcmp(db[i].source_rid, self_rid) == 0) {
//             db[i].color_visited = VISITED;
//             queue[rear++] = i;

//             /* Add directly connected subnets to the routing table */
//             strcpy(rtable[*rtable_size].destination, db[i].subnet);
//             strcpy(rtable[*rtable_size].mask, db[i].mask);
//             strcpy(rtable[*rtable_size].next_hop, db[i].neighbour_rid);
//             (*rtable_size)++;
//         }
//     }
//     /* BFS traversal */
//     while (front < rear) {
//         int current_index = queue[front++];
//         db_struct *current_entry = &db[current_index];

//         /* For each unvisited neighbor entry */
//         for (int i = 0; i < db_size; i++) {
//             if (db[i].valid == VALID && db[i].color_visited == UNVISITED &&
//                 strcmp(db[i].source_rid, current_entry->neighbour_rid) == 0) {

//                 db[i].color_visited = VISITED;
//                 queue[rear++] = i;

//                 /* Add the subnet to the routing table */
//                 strcpy(rtable[*rtable_size].destination, db[i].subnet);
//                 strcpy(rtable[*rtable_size].mask, db[i].mask);
//                 /* Next hop is the next hop from current entry */
//                 strcpy(rtable[*rtable_size].next_hop, current_entry->neighbour_rid);
//                 (*rtable_size)++;
//             }
//         }
//     }
//     reset_color_visited(db, db_size);
// }

// ////////////////////////////////////// PWOSPF Hello Packet ////////////////////////////////////////////////////////////////////////////
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <arpa/inet.h>

// #include "sr_if.h"
// #include "sr_rt.h"
// #include "sr_router.h"
// #include "sr_protocol.h"

// #define PWOSPF_VERSION       2
// #define PWOSPF_TYPE_HELLO    1
// #define OSPF_PROTOCOL_NUMBER 89
// #define ALLSPFROUTERS        0xe0000005  // 224.0.0.5 in hex
// #define PWOSPF_AU_TYPE       0
// #define PWOSPF_AREA_ID       0
// #define HELLO_INTERVAL       10          // Adjust as needed

// #pragma pack(push, 1)

// /* PWOSPF Header Structure */
// struct pwospf_hdr {
//     uint8_t  version;
//     uint8_t  type;
//     uint16_t packet_length;
//     uint32_t router_id;
//     uint32_t area_id;
//     uint16_t checksum;
//     uint16_t autype;
//     uint64_t authentication;
// };

// /* PWOSPF Hello Packet Structure */
// struct pwospf_hello {
//     uint32_t network_mask;
//     uint16_t hello_int;
//     uint16_t padding;
// };

// #pragma pack(pop)

// /* Function to compute the checksum */
// uint16_t pwospf_checksum(uint16_t *data, int length) {
//     uint32_t sum = 0;

//     while (length > 1) {
//         sum += ntohs(*data++);
//         length -= 2;
//     }

//     if (length == 1) {
//         sum += ntohs(*(uint8_t *)data << 8);
//     }

//     while (sum >> 16) {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }

//     return htons(~sum);
// }

// /* Function to create the PWOSPF Hello packet */
// uint8_t *create_pwospf_hello_packet(struct sr_instance *sr, struct sr_if *iface, unsigned int *len) {
//     /* Total PWOSPF packet length */
//     unsigned int pwospf_len = sizeof(struct pwospf_hdr) + sizeof(struct pwospf_hello);

//     /* Allocate memory for the PWOSPF packet */
//     uint8_t *pwospf_packet = (uint8_t *)malloc(pwospf_len);
//     if (!pwospf_packet) {
//         fprintf(stderr, "Memory allocation failed for PWOSPF packet\n");
//         return NULL;
//     }
//     memset(pwospf_packet, 0, pwospf_len);

//     /* PWOSPF Header */
//     struct pwospf_hdr *pwospf_hdr = (struct pwospf_hdr *)pwospf_packet;
//     pwospf_hdr->version = PWOSPF_VERSION;
//     pwospf_hdr->type = PWOSPF_TYPE_HELLO;
//     pwospf_hdr->packet_length = htons(pwospf_len);
//     pwospf_hdr->router_id = iface->ip;    // Router ID is the IP address of eth0
//     pwospf_hdr->area_id = htonl(PWOSPF_AREA_ID);
//     pwospf_hdr->checksum = 0;             // Initialize checksum to zero
//     pwospf_hdr->autype = htons(PWOSPF_AU_TYPE);
//     pwospf_hdr->authentication = 0;       // Authentication is 0

//     /* PWOSPF Hello Packet */
//     struct pwospf_hello *pwospf_hello = (struct pwospf_hello *)(pwospf_packet + sizeof(struct pwospf_hdr));
//     pwospf_hello->network_mask = iface->mask;
//     pwospf_hello->hello_int = htons(HELLO_INTERVAL);
//     pwospf_hello->padding = 0;

//     /* Compute the checksum */
//     pwospf_hdr->checksum = pwospf_checksum((uint16_t *)pwospf_packet, pwospf_len);

//     /* Now create the IP header */
//     unsigned int ip_len = sizeof(sr_ip_hdr_t) + pwospf_len;
//     uint8_t *ip_packet = (uint8_t *)malloc(ip_len);
//     if (!ip_packet) {
//         fprintf(stderr, "Memory allocation failed for IP packet\n");
//         free(pwospf_packet);
//         return NULL;
//     }
//     memset(ip_packet, 0, ip_len);

//     sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)ip_packet;
//     ip_hdr->ip_v = 4;
//     ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
//     ip_hdr->ip_tos = 0;
//     ip_hdr->ip_len = htons(ip_len);
//     ip_hdr->ip_id = htons(0);
//     ip_hdr->ip_off = htons(IP_DF);
//     ip_hdr->ip_ttl = 64;
//     ip_hdr->ip_p = OSPF_PROTOCOL_NUMBER;
//     ip_hdr->ip_src = iface->ip;
//     ip_hdr->ip_dst = htonl(ALLSPFROUTERS);

//     /* Compute IP checksum */
//     ip_hdr->ip_sum = 0;
//     ip_hdr->ip_sum = cksum((uint16_t *)ip_hdr, sizeof(sr_ip_hdr_t));

//     /* Copy PWOSPF packet into IP payload */
//     memcpy(ip_packet + sizeof(sr_ip_hdr_t), pwospf_packet, pwospf_len);

//     /* Now create the Ethernet header */
//     unsigned int ether_len = sizeof(sr_ethernet_hdr_t) + ip_len;
//     uint8_t *ether_frame = (uint8_t *)malloc(ether_len);
//     if (!ether_frame) {
//         fprintf(stderr, "Memory allocation failed for Ethernet frame\n");
//         free(pwospf_packet);
//         free(ip_packet);
//         return NULL;
//     }
//     memset(ether_frame, 0, ether_len);

//     sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)ether_frame;
//     /* Set destination MAC to multicast address for OSPF */
//     eth_hdr->ether_dhost[0] = 0x01;
//     eth_hdr->ether_dhost[1] = 0x00;
//     eth_hdr->ether_dhost[2] = 0x5e;
//     eth_hdr->ether_dhost[3] = 0x00;
//     eth_hdr->ether_dhost[4] = 0x00;
//     eth_hdr->ether_dhost[5] = 0x05;
//     /* Source MAC is interface MAC */
//     memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
//     eth_hdr->ether_type = htons(ethertype_ip);

//     /* Copy IP packet into Ethernet frame */
//     memcpy(ether_frame + sizeof(sr_ethernet_hdr_t), ip_packet, ip_len);

//     /* Set total length */
//     *len = ether_len;

//     /* Clean up */
//     free(pwospf_packet);
//     free(ip_packet);

//     return ether_frame;
// }