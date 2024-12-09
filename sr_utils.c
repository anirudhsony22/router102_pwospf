//////////////////////////////////////////////////////////////////    library

#include <stdio.h>
#include <assert.h>
#include <pthread.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

//////////////////////////////////////////////////////////////////    define

#define MAX_IP_CACHE 1000
#define MAX_ARP_CACHE 100
#define MAX_ARP_CACHE_TIME 10
#define MAX_IP_RETRY_TIME 5
#define ENABLE_PRINT 0

//////////////////////////////////////////////////////////////////    struct and classes

struct arpcache
{
    uint32_t ipaddr;
    uint8_t ether_dhost[6];
    char name[SR_IFACE_NAMELEN];

    uint8_t valid;
    time_t cachetime;
};

struct ipcache
{
    time_t recordtime;
    uint8_t numoftimes;
    time_t lastreqtime;
    uint8_t valid;
    uint32_t nexthop;
    uint8_t nextetheraddr[6];
    char out_ifacename[SR_IFACE_NAMELEN];

    char *in_ifacename;
    uint8_t *packet;
    unsigned int len;
};

//////////////////////////////////////////////////////////////////    Global variables

struct ipcache IP_CACHE[MAX_IP_CACHE];
struct arpcache ARP_CACHE[MAX_ARP_CACHE];
pthread_mutex_t CACHE_LOCK = PTHREAD_MUTEX_INITIALIZER;

//////////////////////////////////////////////////////////////////    Create Methods

uint8_t *create_arp(struct sr_if *iface, uint32_t target_ip)
{
    unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    uint8_t *packet = (uint8_t *)malloc(len);

    memset(packet, 0, len);
    
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

    memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    arp_hdr->ar_hrd = htons(ARPHDR_ETHER);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(ARP_REQUEST);
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iface->ip;
    memset(arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = target_ip;

    return packet;
}

struct arpcache *create_arpcache_entry(uint32_t ipaddr, const uint8_t ether_dhost[6], const char *iface_name) {
    struct arpcache *entry = malloc(sizeof(struct arpcache));
    if (!entry) {
        printf("Memory allocation failed\n");
        return NULL;
    }

    entry->ipaddr = ipaddr;
    memcpy(entry->ether_dhost, ether_dhost, 6);
    strncpy(entry->name, iface_name, SR_IFACE_NAMELEN);
    entry->valid = 1;
    entry->cachetime = time(NULL);

    return entry;
}

struct ipcache *create_ipcache_entry(
    uint8_t *packet,
    unsigned int len,
    const char *in_ifacename,
    uint32_t nexthop,
    const uint8_t *nextetheraddr,
    const char *out_ifacename)
{
    struct ipcache *entry = (struct ipcache *)malloc(sizeof(struct ipcache));
    if (entry == NULL)
    {
        printf("Memory allocation failed while creating an ipcache entry\n");
        return NULL;
    }

    entry->recordtime = time(NULL);
    entry->numoftimes = 0;
    entry->lastreqtime = time(NULL);
    entry->valid = 1;

    entry->nexthop = nexthop;
    strncpy(entry->out_ifacename, out_ifacename, SR_IFACE_NAMELEN);

    entry->in_ifacename = strdup(in_ifacename);
    entry->packet = (uint8_t *)malloc(len);
    if (entry->packet == NULL)
    {
        printf("Failed to allocate memory for packe in the new ipcache entryt\n");
        free(entry->in_ifacename);
        free(entry);
        return NULL;
    }
    memcpy(entry->packet, packet, len);
    entry->len = len;

    return entry;
}

//////////////////////////////////////////////////////////////////    Other Methods

void cleanup_arpcache() {
    time_t cur_time = time(NULL);
    for (int i = 0; i < MAX_ARP_CACHE; i++) {
        if (ARP_CACHE[i].valid == 1) {
            time_t diff = cur_time - ARP_CACHE[i].cachetime;
            if (diff > MAX_ARP_CACHE_TIME) {
                ARP_CACHE[i].valid = 0;
            }
        }
    }
}

uint8_t* lookup_arpcache(u_int32_t target_ip) {
    pthread_mutex_lock(&CACHE_LOCK);

    cleanup_arpcache();
    
    for (int i = 0; i < MAX_ARP_CACHE; i++) {
        if (ARP_CACHE[i].valid == 1) {
            if (target_ip == ARP_CACHE[i].ipaddr) {
                pthread_mutex_unlock(&CACHE_LOCK);
                return ARP_CACHE[i].ether_dhost;
            }
        }
    } 

    pthread_mutex_unlock(&CACHE_LOCK);
    return NULL;
}

int buffer_arp_entry(struct arpcache *new_entry) {
    pthread_mutex_lock(&CACHE_LOCK);

    cleanup_arpcache(); 

    for (int i = 0; i < MAX_ARP_CACHE; i++) {
        if (ARP_CACHE[i].ipaddr == new_entry->ipaddr) {
            memcpy(ARP_CACHE[i].ether_dhost, new_entry->ether_dhost, 6);
            strncpy(ARP_CACHE[i].name, new_entry->name, SR_IFACE_NAMELEN);
            ARP_CACHE[i].cachetime = time(NULL);
            ARP_CACHE[i].valid = 1; 
            pthread_mutex_unlock(&CACHE_LOCK);
            return 1;
        }
    }

    for (int i = 0; i < MAX_ARP_CACHE; i++) {
        if (!ARP_CACHE[i].valid) {
            ARP_CACHE[i] = *new_entry;
            ARP_CACHE[i].valid = 1;
            pthread_mutex_unlock(&CACHE_LOCK);
            return 1;
        }
    }

    pthread_mutex_unlock(&CACHE_LOCK);
    return 0;
}


int buffer_ip_packet(struct ipcache *new_entry)
{
    pthread_mutex_lock(&CACHE_LOCK);
    for (int i = 0; i < MAX_IP_CACHE; i++)
    {
        if (IP_CACHE[i].valid == 0)
        {                            
            IP_CACHE[i] = *new_entry;
            IP_CACHE[i].valid = 1;
            pthread_mutex_unlock(&CACHE_LOCK);
            return 1;
        }
    }

    pthread_mutex_unlock(&CACHE_LOCK);
    return 0;
}

void send_relevent_ipcache_entries(struct arpcache* arpcache_entry,  struct sr_instance *sr) 
{
    pthread_mutex_lock(&CACHE_LOCK);
    int ip_packet_counter=0;
    for (int i = 0; i < MAX_IP_CACHE; i++)
    {
        if (IP_CACHE[i].valid == 1){
            ip_packet_counter+=1;
        }
        if (IP_CACHE[i].valid == 1 && IP_CACHE[i].nexthop == arpcache_entry->ipaddr)
        {
            uint8_t* packet = IP_CACHE[i].packet;
            struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
            struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

            struct sr_if *next_iface = sr_get_interface(sr, IP_CACHE[i].out_ifacename);
            
            memcpy(eth_hdr->ether_dhost, arpcache_entry->ether_dhost, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, next_iface->addr, ETHER_ADDR_LEN);

            sr_send_packet(sr, packet, IP_CACHE[i].len, next_iface->name);
            IP_CACHE[i].valid = 0;
        }
    }
    pthread_mutex_unlock(&CACHE_LOCK);
}

void initialize_variables()
{
    for (int i = 0; i < MAX_IP_CACHE; i++)
    {
        IP_CACHE[i].valid = 0;
    }

    for (int i = 0; i < MAX_ARP_CACHE; i++)
    {
        ARP_CACHE[i].valid = 0;
    }
}

uint16_t get_checksum(uint16_t *buf, int count)
{
    register uint32_t sum = 0;

    while (count--)
    {
        sum += *buf++;
        if (sum & 0xFFFF0000)
        {
            sum &= 0xFFFF;
            sum++;
        }
    }
    sum = ~sum;
    return sum ? sum : 0xffff;
}

int validate_ipchecksum(uint8_t *packet)
{
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

    uint16_t temp_sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    int header_len = ip_hdr->ip_hl * 4;
    uint16_t cksum = get_checksum((uint16_t *)ip_hdr, header_len / 2);
    ip_hdr->ip_sum = temp_sum;

    return (cksum == temp_sum);
}

int is_valid_ip_packet(uint8_t *packet)
{

    int is_correct_checksum = validate_ipchecksum(packet);
    if (!is_correct_checksum)
    {
        printf("checksum is wrong\n");
        return 0;
    }

    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    if ((ip_hdr->ip_ttl - 1) == 0)
    {
        printf("TTL 0 found");
        return 0;
    }
    return 1;
}

int is_valid_ethernet_packet(unsigned int len)
{
    if (len < sizeof(struct sr_ethernet_hdr))
    {
        fprintf(stderr, "** Error: packet is too short\n");
        return 0;
    }
    return 1;
}

void print_drop()
{
    printf("Dropping the packet!!!\n");
}

void print_message(const char *message)
{
    printf("-------- %s\n", message);
}

void update_ethernet_header_arp_reply(uint8_t *packet, struct sr_if *iface)
{
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
}

void prepare_arp_reply(struct sr_instance *sr, struct sr_if *iface, struct sr_arphdr *req_hdr, unsigned char *src_mac, char *interface)
{
    req_hdr->ar_op = htons(ARP_REPLY);

    memcpy(req_hdr->ar_tha, req_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(req_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);

    uint32_t temp_ip = req_hdr->ar_sip;
    req_hdr->ar_sip = req_hdr->ar_tip;
    req_hdr->ar_tip = temp_ip;
}

void populate_ip_header(uint8_t *packet)
{
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

    ip_hdr->ip_ttl--;

    ip_hdr->ip_sum = 0;
    int header_len = ip_hdr->ip_hl * 4;
    ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, header_len / 2);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////    Handling Methods

uint16_t compute_ip_checksum(uint16_t *addr, int len) {
    uint32_t sum = 0;
    for (; len > 1; len -= 2) {
        sum += *addr++;
    }
    if (len == 1) {
        sum += *(uint8_t *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

uint8_t *create_dummy_ip_packet(int *packet_size) {
    int size = sizeof(struct ip) + 20;
    uint8_t *packet = malloc(size);

    if (!packet) {
        perror("Failed to allocate packet");
        return NULL;
    }
    memset(packet, 0, size);
    struct ip *ip_hdr = (struct ip *)packet;
    ip_hdr->ip_hl = 5;  // IP header length (5 * 4 = 20 bytes)
    ip_hdr->ip_v = 4;   // IP version 4
    ip_hdr->ip_tos = 0; // Type of service
    ip_hdr->ip_len = htons(size); // Total packet length
    ip_hdr->ip_id = htons(54321); // ID of this packet
    ip_hdr->ip_off = 0; // Fragment offset
    ip_hdr->ip_ttl = 64; // Time to live
    ip_hdr->ip_p = IPPROTO_TCP; // Protocol (TCP)
    ip_hdr->ip_sum = 0; // Checksum (0 for now)
    ip_hdr->ip_src.s_addr = htonl(2887586454); // Source IP
    ip_hdr->ip_dst.s_addr = htonl(2887587450); // Destination IP

    ip_hdr->ip_sum = compute_ip_checksum((uint16_t *)ip_hdr, ip_hdr->ip_hl * 4);

    *packet_size = size;

    return packet;
}




void handle_arp(struct sr_instance *sr,
                uint8_t *packet,
                unsigned int len,
                char *interface)
{

    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));
    struct sr_if *iface = sr_get_interface(sr, interface);
    if (ntohs(arp_hdr->ar_op) == ARP_REQUEST)
    {
        if (iface && iface->ip == arp_hdr->ar_tip)
        {
            prepare_arp_reply(sr, iface, arp_hdr, eth_hdr->ether_shost, interface);
            update_ethernet_header_arp_reply(packet, iface);
            sr_send_packet(sr, packet, len, interface);
        }
    } else {
        struct arpcache* new_arpcache = create_arpcache_entry(arp_hdr->ar_sip, arp_hdr->ar_sha, interface);
        int success = buffer_arp_entry(new_arpcache);

        if (!success) {
            print_message("Alert!!!: ARP buffer full! Cannot put the arp entry into the buffer!");
        } else {
            send_relevent_ipcache_entries(new_arpcache, sr);
        }
    }
}

void handle_ip(uint8_t *packet,
               struct sr_instance *sr,
               unsigned int len,
               char *interface
)
{
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    int protocol = ip_hdr->ip_p;
    if (protocol==IPPROTO_ICMP){

        printf("Rec'd ICMP\n");

        struct icmp* icmphdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
        struct sr_if *iface = sr_get_interface(sr, interface);

        struct sr_if *match_iface = NULL;
        struct sr_if* iface_header = sr->if_list;
        while (iface_header != NULL) {
            if(ip_hdr->ip_dst.s_addr==iface_header->ip){
                match_iface = iface_header;
                break;
            }
            iface_header = iface_header->next;
        }

        if(match_iface != NULL){
            //todo : traverse through all ifaces
            if(icmphdr->type==0){
                return;
            }
            icmphdr->type = 0;
            icmphdr->checksum = 0;
            icmphdr->checksum = get_checksum((uint16_t *)icmphdr, sizeof(struct icmp));

            u_int32_t source_ip = ip_hdr->ip_dst.s_addr;
            ip_hdr->ip_dst = ip_hdr->ip_src;
            ip_hdr->ip_src.s_addr = source_ip;
            ip_hdr->ip_ttl = 64;
            ip_hdr->ip_sum = 0;
            int header_len = ip_hdr->ip_hl * 4;
            ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, header_len / 2);

            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
            printf("Sending back the ICMP: %s\n", interface);
            print_packet_details(packet);
            print_icmp_header(icmphdr);

            sr_send_packet(sr, packet, len, interface);
            return;
        }

    }

    struct sr_rt *routing_table = sr->routing_table;

    struct sr_rt *rt_header = routing_table;
    struct in_addr *next_hop = NULL;
    struct in_addr mask;
    struct in_addr nxthop;
    mask.s_addr = 0;
    nxthop.s_addr = 0;
    char next_interface[SR_IFACE_NAMELEN];

    while (rt_header != NULL)
    {
        if ((rt_header->dest.s_addr & rt_header->mask.s_addr) == ((ip_hdr->ip_dst.s_addr) & rt_header->mask.s_addr) && mask.s_addr <= ntohl(rt_header->mask.s_addr))
        {
            mask.s_addr = ntohl(rt_header->mask.s_addr);
            nxthop.s_addr = rt_header->gw.s_addr;
            memcpy(next_interface, rt_header->interface, sizeof(next_interface));
        }
        rt_header = rt_header->next;
    }

    if (nxthop.s_addr == 0)
    {
        nxthop.s_addr = ip_hdr->ip_dst.s_addr;
                        !ENABLE_PRINT ? :  print_message("handle ip B");
    }

    struct sr_if* next_iface = sr_get_interface(sr, next_interface);

    uint8_t* target_mac = lookup_arpcache(nxthop.s_addr);
    if (target_mac == NULL) {
        struct ipcache* new_ipcache = create_ipcache_entry(packet, len, interface, nxthop.s_addr, NULL, next_interface);
        int success = buffer_ip_packet(new_ipcache);

        if (success) {
            uint8_t *arp_packet = create_arp(next_iface, nxthop.s_addr);
            sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), next_interface);
        } else {
            //todo: Send ICMP & check other places         
            return;
        }
    } else {
        memcpy(eth_hdr->ether_dhost, target_mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, next_iface->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, packet, len, next_interface);
    }
}


///////////////////////////////////////////////////////////////////////////////////////////// Dumps



void print_ip_address(uint32_t ar_sip) {
    uint32_t ip_host_order = ntohl(ar_sip);

    unsigned char bytes[4];
    bytes[0] = (ip_host_order >> 24) & 0xFF;
    bytes[1] = (ip_host_order >> 16) & 0xFF;
    bytes[2] = (ip_host_order >> 8) & 0xFF;
    bytes[3] = ip_host_order & 0xFF;

    printf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void print_mac_address(const char* label, const unsigned char* mac) {
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", label, 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ipcache_stats() {
    pthread_mutex_lock(&CACHE_LOCK);  
    printf("Ipcache stats begin --------------------------------------------------------- \n");

    int count = 0;
    for (int i = 0; i < MAX_IP_CACHE; i++)
    {
        if (IP_CACHE[i].valid == 1)
        {              
            count++;

            uint8_t* packet = IP_CACHE[i].packet;
            struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

            printf("Source IP: ");
            print_ip_address(ip_hdr->ip_src.s_addr);
            printf("   Destination IP: ");
            print_ip_address(ip_hdr->ip_dst.s_addr);
            printf("\n");
        }
    }
    printf("Total valid ipcache: %d\n",count);
    printf("Ipache stats end --------------------------------------------------------- \n");
    pthread_mutex_unlock(&CACHE_LOCK); 
}

void print_arppcache_stats() {
    pthread_mutex_lock(&CACHE_LOCK);  
    printf("Arpcache stats begin --------------------------------------------------------- \n");

    int count = 0;
    for (int i = 0; i < MAX_ARP_CACHE; i++)
    {
        if (ARP_CACHE[i].valid == 1)
        {              
            count++;

            printf("ARP IP: ");
            print_ip_address(ARP_CACHE[i].ipaddr);
            printf("   ARP MAC: ");
            print_mac_address("", ARP_CACHE[i].ether_dhost);
            printf("\n");
        }
    }

    printf("Total valid arpcache: %d\n",count);
    printf("Arpcache stats end --------------------------------------------------------- \n");
    pthread_mutex_unlock(&CACHE_LOCK); 
}

void print_stats() {
    print_arppcache_stats();
    print_ipcache_stats();
}

void print_new_packet_stats(uint8_t* packet, char* interface) {
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

        if (ntohs(arp_hdr->ar_op) == ARP_REQUEST) {
            printf("*** New packet *** Type: ARP REQUEST IFACE: %s", interface);
        } else {
            printf("*** New packet *** Type: ARP REPLY IFACE: %s", interface);
        }

        printf("  Source IP: ");
        print_ip_address(arp_hdr->ar_sip);
        printf("  Target IP: ");
        print_ip_address(arp_hdr->ar_tip);
    } else {
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
        printf("*** New packet *** Type: IP IFACE: %s", interface);
        printf("  Source IP: ");
        print_ip_address(ip_hdr->ip_src.s_addr);
        printf("  Target IP: ");
        print_ip_address(ip_hdr->ip_dst.s_addr);
    }

    printf("\n");
}

void* ipcache_thread(void* sr_arg) {
    struct sr_instance *sr = sr_arg;

    while (1) {
        // printf("Thread is running...\n");

        pthread_mutex_lock(&CACHE_LOCK);  

        for (int i = 0; i < MAX_IP_CACHE; i++)
        {
            if (IP_CACHE[i].valid == 1)
            {
                if (IP_CACHE[i].numoftimes < MAX_IP_RETRY_TIME) {
                    struct ipcache* new_ipcache = create_ipcache_entry(IP_CACHE[i].packet, IP_CACHE[i].len
                                    , IP_CACHE[i].in_ifacename, IP_CACHE[i].nexthop, NULL, IP_CACHE[i].out_ifacename);

                    struct sr_if *next_iface = sr_get_interface(sr, IP_CACHE[i].out_ifacename);

                    uint8_t *arp_packet = create_arp(next_iface, IP_CACHE[i].nexthop);
                    sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), IP_CACHE[i].out_ifacename);
                    // printf("***********################ Retrying!\n");
                    // printf("************Try number: %d **********", IP_CACHE[i].numoftimes);
                    IP_CACHE[i].numoftimes++;
                } else {
                    //todo: send icmp
                    IP_CACHE[i].valid = 0;
                }
            }
        }

        pthread_mutex_unlock(&CACHE_LOCK); 

        sleep(1);
    }
    return NULL;
}

//     struct in_addr ip_addr;
//     ip_addr.s_addr = ip;
//     return inet_ntoa(ip_addr);
// }

// // Function to print MAC address in human-readable format

// // Function to print the contents of the ARP header
// void print_arp_header(const struct sr_arphdr* arp_hdr) {
//     printf("Hardware type: %u\n", ntohs(arp_hdr->ar_hrd));
//     printf("Protocol type: %u\n", ntohs(arp_hdr->ar_pro));
//     printf("Hardware address length: %u bytes\n", arp_hdr->ar_hln);
//     printf("Protocol address length: %u bytes\n", arp_hdr->ar_pln);
//     printf("ARP opcode: %u\n", ntohs(arp_hdr->ar_op));
    
//     print_mac_address("Sender hardware address", arp_hdr->ar_sha);
//     printf("Sender IP address: %s\n", ip_to_string(arp_hdr->ar_sip));
    
//     print_mac_address("Target hardware address", arp_hdr->ar_tha);
//     printf("Target IP address: %s\n", ip_to_string(arp_hdr->ar_tip));
// }



// assert(packet);
// assert(len);
// assert(interface);
// assert(nxthop.s_addr);
// assert(next_interface);

// struct ipcache* new_en = create_ipcache_entry(packet, len, interface, nxthop.s_addr, NULL, next_interface);
// buffer_ip_packet(new_en);

void print_ethernet_header(struct sr_ethernet_hdr* eth_hdr) {
    printf("Destination MAC: %s\n", eth_hdr->ether_dhost);
    printf("Source MAC: %s\n", eth_hdr->ether_shost);
    printf("Type: %hu\n", ntohs(eth_hdr->ether_type));
}

/* Helper function to print IP headers */
void print_ip_header(struct ip* ip_hdr) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);   
    printf("\n--- IP Header ---\n");
    printf("Version: %d\n", ip_hdr->ip_v);
    printf("Header Length: %d bytes\n", ip_hdr->ip_hl * 4);
    printf("Type of Service: %d\n", ip_hdr->ip_tos);
    printf("Total Length: %d\n", ntohs(ip_hdr->ip_len));
    printf("ID: %d\n", ntohs(ip_hdr->ip_id));
    printf("Fragment Offset: %d\n", ntohs(ip_hdr->ip_off));
    printf("TTL: %d\n", ip_hdr->ip_ttl);
    printf("Protocol: %d\n", ip_hdr->ip_p);
    printf("Checksum: %d\n", ntohs(ip_hdr->ip_sum));
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
}

/* General function to print packet details */
void print_packet_details(uint8_t* packet) {
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    printf("\n Src MAC: ");
    print_mac_address("", eth_hdr->ether_shost);
    printf(" Dest MAC: ");
    print_mac_address("", eth_hdr->ether_dhost);
    printf("\n");
    print_ip_header(ip_hdr);
}

void print_icmp_header(struct icmp* icmphdr) {
    printf("\n--- ICMP Header ---\n");
    printf("Type: %d\n", icmphdr->type);
    printf("Code: %d\n", icmphdr->code);
    printf("Checksum: %d\n", ntohs(icmphdr->checksum));
}