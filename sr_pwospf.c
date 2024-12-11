/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_rt.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>


/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);
char* get_ipstr(uint32_t ip_big_endian);
void send_pwospf_hello(struct sr_instance *sr, struct sr_if *iface);
// void send_pwospf_lsu2(struct sr_instance *sr, struct pwospf_if *pw_iface);
void create_routing_table(uint32_t source_router_id, struct sr_instance *sr);
void print_routing_table(struct sr_rt* rt);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
    pthread_mutex_init(&(sr->ospf_subsys->lock1), 0);
    pthread_mutex_init(&(sr->ospf_subsys->lock2), 0);
    pthread_mutex_init(&(sr->ospf_subsys->lock3), 0);
    

    /* -- handle subsystem initialization here! -- */
    sr->ospf_subsys->router = malloc(sizeof(struct pwospf_router));
    pthread_mutex_init(&sr->ospf_subsys->router->lock, NULL);
    sr->ospf_subsys->router->area_id = PWOSPF_AREA_ID;
    sr->ospf_subsys->router->lsuint = 30; /* Default 30 seconds */
    sr->ospf_subsys->router->interfaces = NULL;
    sr->ospf_subsys->router->sequence_number = 0;
    sr->ospf_subsys->router->router_id = sr->if_list->ip;

    struct sr_if* iface = sr->if_list;
    struct pwospf_if* prev_pw_iface = NULL;

    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
        ls_db[i].state = 0;    
    }
    init_seq();
    
    while (iface) {
        struct pwospf_if* pw_iface = malloc(sizeof(struct pwospf_if));

        pw_iface->iface = iface;
        pw_iface->helloint = HELLO_INTERVAL;
        pw_iface->neighbor_id = 0;
        pw_iface->neighbor_ip = 0;
        pw_iface->last_hello_time = 0;
        pw_iface->next = NULL;

        if (prev_pw_iface) {
            prev_pw_iface->next = pw_iface;
        } else {
            sr->ospf_subsys->router->interfaces = pw_iface;
        }

        update_lsdb(sr->ospf_subsys->router->router_id, 0, iface->ip&iface->mask, iface->mask, 1, iface->name);
        
        prev_pw_iface = pw_iface;
        iface = iface->next;
    }
    create_routing_table(sr->ospf_subsys->router->router_id, sr);
    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    struct pwospf_router* router = sr->ospf_subsys->router;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */
        struct sr_if* iface = sr->if_list;
        while (iface) {
            send_pwospf_hello(sr, iface);
            iface = iface->next;
        }


        //L3 Lock
        if (pthread_mutex_lock(&sr->ospf_subsys->lock3)) assert(0); 
        
        struct pwospf_if* interfaces = sr->ospf_subsys->router->interfaces;
        int change1=0;
        time_t now = time(NULL);
        struct link_state_entry track_lsdb[3];//Todo: Free this memory
        int track_count=0;
        while(interfaces) {
            if((interfaces->neighbor_id != 0)&&(now-interfaces->last_hello_time)>HELLO_TIMEOUT){
                interfaces->neighbor_id = 0;
                change1=1;

                track_lsdb[track_count].source_router_id = sr->ospf_subsys->router->router_id;
                track_lsdb[track_count].neighbor_router_id = 0;
                track_lsdb[track_count].subnet = interfaces->iface->ip&interfaces->iface->mask;
                printf("Inside Invalidation, IP, Mask: %s \t %s\n", get_ipstr(interfaces->iface->ip), get_ipstr(interfaces->iface->mask));
                track_lsdb[track_count].mask = interfaces->iface->mask;
                strncpy(track_lsdb[track_count].interface, interfaces->iface->name, SR_IFACE_NAMELEN);
                track_count++;
            }
            interfaces = interfaces->next;
        }
        
        send_pwospf_lsu(sr); // send always lsu
        if(change1){
            printf("Change1 (Link Down) detected\n");
        }
        if (pthread_mutex_unlock(&sr->ospf_subsys->lock3)) assert(0); 
        //L3 Unlock

        if(change1){
            //L2 Lock
            if (pthread_mutex_lock(&sr->ospf_subsys->lock2)) assert(0); 
            //LSDB Update
            for(int i=0;i<track_count;i++){
                update_lsdb(track_lsdb[i].source_router_id,
                            track_lsdb[i].neighbor_router_id,
                            track_lsdb[i].subnet,
                            track_lsdb[i].mask,
                            1,
                            track_lsdb[i].interface);
            }

            printf("Creating table from Invalidation\n");
            // create_routing_table(sr->ospf_subsys->router->router_id, sr);
            // print_routing_table(sr->dynamic_routing_table);
            if (pthread_mutex_unlock(&sr->ospf_subsys->lock2)) assert(0); 
            //L2 Unlock
        }

        print_link_state_table();
        sleep(5);
        printf(" pwospf subsystem awake \n");
    };
    return NULL;
} /* -- run_ospf_thread -- */

void send_pwospf_hello(struct sr_instance *sr, struct sr_if *iface) {
    unsigned int pwospf_len = sizeof(pwospf_hdr_t) + sizeof(pwospf_hello_t);
    
    uint8_t *pwospf_packet = (uint8_t *)malloc(pwospf_len);

    memset(pwospf_packet, 0, pwospf_len);
    
    /* PWOSPF Header */
    pwospf_hdr_t *pwospf_hdr = (pwospf_hdr_t *)pwospf_packet;
    pwospf_hdr->version = PWOSPF_VERSION;
    pwospf_hdr->type = PWOSPF_TYPE_HELLO;
    pwospf_hdr->packet_length = htons(pwospf_len);
    pwospf_hdr->router_id = (sr->ospf_subsys->router->router_id);
    // pwospf_hdr->area_id = (PWOSPF_AREA_ID);
    // pwospf_hdr->checksum = 0;             /* Initialize checksum to zero */
    // pwospf_hdr->autype = (PWOSPF_AU_TYPE);
    // pwospf_hdr->authentication = 0;       /* Authentication is 0 */
    
    /* PWOSPF Hello Packet */
    pwospf_hello_t *pwospf_hello = (pwospf_hello_t *)(pwospf_packet + sizeof(pwospf_hdr_t));
    pwospf_hello->network_mask = (iface->mask);
    pwospf_hello->hello_int = htons(HELLO_INTERVAL);
    pwospf_hello->padding = 0;
    // int checksum_len = pwospf_len - sizeof(pwospf_hdr->authentication);
    // pwospf_hdr->checksum = get_checksum((uint16_t *)pwospf_packet, checksum_len / 2);
    
    // /* Now create the IP header */
    unsigned int ip_len = sizeof(struct ip) + pwospf_len;
    uint8_t *ip_packet = (uint8_t *)malloc(ip_len);
    memset(ip_packet, 0, ip_len);
    struct ip *ip_hdr = (struct ip *)ip_packet;
    ip_hdr->ip_hl = 5;  /* IP header length (5 * 4 = 20 bytes) */
    ip_hdr->ip_v = 4;   /* IP version 4 */
    ip_hdr->ip_tos = 0; /* Type of service */
    ip_hdr->ip_len = htons(ip_len); /* Total packet length */
    ip_hdr->ip_id = htons(0); /* ID of this packet */
    ip_hdr->ip_off = htons(IP_DF); /* Fragment offset */
    ip_hdr->ip_ttl = 64; /* Time to live */
    ip_hdr->ip_p = OSPF_PROTOCOL_NUMBER; /* Protocol number for OSPF */
    ip_hdr->ip_src.s_addr = (iface->ip); /* Source IP */
    ip_hdr->ip_dst.s_addr = htonl(ALLSPFROUTERS); /* Destination IP (224.0.0.5) */ //Big Endian
    
    /* Compute IP checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, ip_hdr->ip_hl * 2);
    memcpy(ip_packet + sizeof(struct ip), pwospf_packet, pwospf_len);
    
    /* Now create the Ethernet header */
    unsigned int ether_len = sizeof(struct sr_ethernet_hdr) + ip_len;
    uint8_t *ether_frame = (uint8_t *)malloc(ether_len);
    memset(ether_frame, 0, ether_len);
    
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)ether_frame;
    /* Set destination MAC to multicast address for OSPF (01:00:5e:00:00:05) */
    eth_hdr->ether_dhost[0] = 0x01;
    eth_hdr->ether_dhost[1] = 0x00;
    eth_hdr->ether_dhost[2] = 0x5e;
    eth_hdr->ether_dhost[3] = 0x00;
    eth_hdr->ether_dhost[4] = 0x00;
    eth_hdr->ether_dhost[5] = 0x05;
    /* Source MAC is interface MAC */
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ETHERTYPE_IP); /* Ethernet type for IP */
    
    // /* Copy IP packet into Ethernet frame */
    memcpy(ether_frame + sizeof(struct sr_ethernet_hdr), ip_packet, ip_len);
    sr_send_packet(sr, ether_frame, ether_len, iface->name);
    // free(pwospf_packet);
    // free(ip_packet);
    // free(ether_frame);
}


void send_pwospf_lsu(struct sr_instance *sr) {
    struct pwospf_router *router = sr->ospf_subsys->router;
    if(router){
        
        struct pwospf_if* interfaces = router->interfaces;
        advertisement_t *ads = (advertisement_t *)malloc(MAX_ADS * sizeof(advertisement_t));

        int num_ads = 0;
        printf("::::::::::::::::::::LSU Advertisement::::::::::::::::\n");
        while (interfaces) {
            ads[num_ads].subnet = (interfaces->iface->ip & interfaces->iface->mask);
            ads[num_ads].mask = (interfaces->iface->mask);
            ads[num_ads].router_id = (interfaces->neighbor_id);
            printf("%d\n", num_ads+1);
            printf("Subnet: %s\n", get_ipstr(ads[num_ads].subnet));
            printf("Mask: %s\n", get_ipstr(ads[num_ads].mask));
            printf("Router ID: %s\n", get_ipstr(ads[num_ads].router_id));
            num_ads++;
            interfaces = interfaces->next;
        }
        

        unsigned int lsu_len = sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t) + num_ads * sizeof(advertisement_t);
        uint8_t *lsu_packet = (uint8_t *)malloc(lsu_len);
        memset(lsu_packet, 0, lsu_len);

        pwospf_hdr_t *pwospf_hdr = (pwospf_hdr_t *)lsu_packet;
        pwospf_hdr->version = PWOSPF_VERSION;
        pwospf_hdr->type = PWOSPF_TYPE_LSU;
        pwospf_hdr->packet_length = htons(lsu_len);
        pwospf_hdr->router_id = router->router_id;

        lsu_hdr_t *lsu_hdr = (lsu_hdr_t *)(lsu_packet + sizeof(pwospf_hdr_t));
        lsu_hdr->sequence = (router->sequence_number++);
        lsu_hdr->ttl = DEFAULT_LSU_TTL;
        lsu_hdr->num_ads = (num_ads);

        memcpy(lsu_packet + sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t), ads, num_ads * sizeof(advertisement_t));

        //Send to each interface
        interfaces = router->interfaces;
        while (interfaces) {
            unsigned int ip_len = sizeof(struct ip) + lsu_len;
            uint8_t *ip_packet = (uint8_t *)malloc(ip_len);
            memset(ip_packet, 0, ip_len);

            struct ip *ip_hdr = (struct ip *)ip_packet;
            ip_hdr->ip_hl = 5;
            ip_hdr->ip_v = 4;
            ip_hdr->ip_tos = 0;
            ip_hdr->ip_len = htons(ip_len);
            ip_hdr->ip_id = htons(0);
            ip_hdr->ip_off = htons(IP_DF);
            ip_hdr->ip_ttl = 64;
            ip_hdr->ip_p = OSPF_PROTOCOL_NUMBER;
            ip_hdr->ip_src.s_addr = interfaces->iface->ip;
            ip_hdr->ip_dst.s_addr = interfaces->neighbor_ip;

            ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, ip_hdr->ip_hl * 2);//Verify if you need this in htons
            memcpy(ip_packet + sizeof(struct ip), lsu_packet, lsu_len);

            unsigned int ether_len = sizeof(struct sr_ethernet_hdr) + ip_len;
            uint8_t *ether_frame = (uint8_t *)malloc(ether_len);
            memset(ether_frame, 0, ether_len);

            struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)ether_frame;
            eth_hdr->ether_dhost[0] = 0x01;
            eth_hdr->ether_dhost[1] = 0x00;
            eth_hdr->ether_dhost[2] = 0x5e;
            eth_hdr->ether_dhost[3] = 0x00;
            eth_hdr->ether_dhost[4] = 0x00;
            eth_hdr->ether_dhost[5] = 0x05;

            memcpy(eth_hdr->ether_shost, interfaces->iface->addr, ETHER_ADDR_LEN);
            eth_hdr->ether_type = htons(ETHERTYPE_IP);

            memcpy(ether_frame + sizeof(struct sr_ethernet_hdr), ip_packet, ip_len);

            sr_send_packet(sr, ether_frame, ether_len, interfaces->iface->name);

            free(ip_packet);
            free(ether_frame);

            interfaces = interfaces->next;
        }

        free(lsu_packet);
        free(ads);
    }
}

void forward_lsu(struct sr_instance* sr, uint8_t *packet, int len, struct sr_if* iface) {
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

    sr_send_packet(sr, packet, len, iface->name);
}

char* get_ipstr(uint32_t ip_big_endian) {
    uint32_t ip_host_order = ntohl(ip_big_endian);

    char* result = (char*)malloc(16);
    if (result == NULL) {
        return NULL;
    }
    sprintf(result, "%u.%u.%u.%u",
            (ip_host_order >> 24) & 0xFF,
            (ip_host_order >> 16) & 0xFF,
            (ip_host_order >> 8) & 0xFF,
            ip_host_order & 0xFF);
    return result;
}

void update_lsdb(uint32_t source_id, uint32_t neighbor_id, uint32_t subnet, uint32_t mask, int is_current_id, char *ifname) {
    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
        if (ls_db[i].source_router_id == source_id && (ls_db[i].subnet == subnet)) {
            ls_db[i].neighbor_router_id = neighbor_id;
            ls_db[i].subnet = subnet;
            ls_db[i].last_update_time = time(NULL);
            ls_db[i].mask = mask;
            ls_db[i].state = 0;
            strncpy(ls_db[i].interface, ifname, SR_IFACE_NAMELEN);
            return;
        }
    }
    for (int i=0; i<MAX_LINK_STATE_ENTRIES; i++){
        if(ls_db[i].state==0){
            ls_db[i].source_router_id = source_id;
            ls_db[i].neighbor_router_id = neighbor_id;
            ls_db[i].subnet = subnet;
            ls_db[i].last_update_time = time(NULL);
            ls_db[i].mask = mask;
            ls_db[i].state = 1;
            strncpy(ls_db[i].interface, ifname, SR_IFACE_NAMELEN);
            return;
        }
    }
}

void create_routing_table(uint32_t source_router_id, struct sr_instance* sr) {

    uint32_t qt[MAX_LINK_STATE_ENTRIES];//Todo: Free this memory
    uint32_t next_hop[MAX_LINK_STATE_ENTRIES];//Todo: Free this memory
    struct sr_rt *temp_routing_table = malloc(sizeof(struct sr_rt) * MAX_LINK_STATE_ENTRIES); // Allocate memory dynamically
    // struct sr_rt *temp = temp_routing_table;
    // while (temp_routing_table) {
    //     struct sr_rt* next = temp_routing_table->next;
    //     free(temp_routing_table);
    //     temp_routing_table = next;
    // }
    // temp_routing_table=temp;

    int temp_rt_counter = 0;
    int rear = 0;
    int front = 0;
    int rt_index = 0; // Start index for routing table

    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++){
        ls_db[i].color=WHITE;
    }

    qt[0] = source_router_id;
    rear++;
    next_hop[0] = 0;

    while(front<rear){
        uint32_t current_router_id = qt[front];
        uint32_t current_next_hop = next_hop[front];

        for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
            if (ls_db[i].state == 1 && ls_db[i].source_router_id == current_router_id) {
                
                uint32_t curr_subnet = ls_db[i].subnet;
                int link_used = 0;

                //Check if this subnet was used before (that is already present in the routing table)
                for (int j=0; j<temp_rt_counter;j++){
                    if(temp_routing_table[j].dest.s_addr == curr_subnet) {
                        link_used=1;
                        break;
                    }
                }

                if(link_used==0){
                    qt[rear] = ls_db[i].neighbor_router_id; // Ensure null termination
                    next_hop[rear] = (source_router_id == current_router_id) ? ls_db[i].neighbor_router_id :
                                        current_next_hop;                    

                    // add to dynamic router
                    temp_routing_table[temp_rt_counter].dest.s_addr = curr_subnet;
                    temp_routing_table[temp_rt_counter].gw.s_addr = next_hop[rear];
                    temp_routing_table[temp_rt_counter].mask.s_addr = ls_db[i].mask;
                    strncpy(temp_routing_table[temp_rt_counter].interface, ls_db[i].interface, SR_IFACE_NAMELEN);
                    temp_routing_table[temp_rt_counter].next = NULL;

                    if (temp_rt_counter > 0) {
                        temp_routing_table[temp_rt_counter - 1].next = &temp_routing_table[temp_rt_counter];
                    }
                
                    temp_rt_counter++;
                    rear++;
                }
                                
                ls_db[i].color = BLACK;
            }
        }
        front++;
    }


    // if (sr->dynamic_routing_table != NULL) {
    //     free(sr->dynamic_routing_table);
    // }

    struct sr_rt* prev_drt = NULL;
    for (int j=0; j<temp_rt_counter;j++){
        struct sr_rt* new_drt = malloc(sizeof(struct sr_rt));

        new_drt->dest.s_addr = temp_routing_table[j].dest.s_addr ;
        new_drt->gw.s_addr = temp_routing_table[j].gw.s_addr;
        new_drt->mask.s_addr = temp_routing_table[j].mask.s_addr;
        strncpy(new_drt->interface, temp_routing_table[j].interface, SR_IFACE_NAMELEN);
        new_drt->next = NULL;

        if (prev_drt != NULL) {
            prev_drt->next = new_drt;
        } else {
            sr->dynamic_routing_table = new_drt;
        }
        prev_drt = new_drt;
    }

    return;
}

void init_seq(){
    for(int i=0;i<MAX_ROUTERS;i++){
        seq[i].last_sequence_num=-1;
    }
}

int is_valid_sequence(uint32_t source, uint32_t check){
    printf("Seq number %d\n", check);
    for (int i = 0; i < MAX_ROUTERS; i++) {
        if (seq[i].source_router_id == source) {
            if(seq[i].last_sequence_num>=check){
                return 0;
            }
            seq[i].last_sequence_num=check;
            return 1;
        }
    }
    for (int i = 0; i < MAX_ROUTERS; i++) {
        if(seq[i].last_sequence_num==-1){
            seq[i].source_router_id = source;
            seq[i].last_sequence_num = check;
            return 1;
        }
    }
}

void clear_lsdb(uint32_t source_id){
    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++){
        if(ls_db[i].source_router_id == source_id){
            ls_db[i].state = 0; //Invalidate it
        }
    }
}

void print_link_state_table() {
    printf("-------------------------------------------------------------\n");
    printf("| Source Router | Neighbor Router | Subnet       | Mask       | Last Hello Time       | State  | Color |\n");
    printf("-------------------------------------------------------------\n");

    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
        // print_ip(ls_db[i].source_router_id);
        // printf(" | ");
        // print_ip(ls_db[i].neighbor_router_id);
        // printf(" | ");
        // print_ip(ls_db[i].subnet);
        // printf(" | ");
        // print_ip(ls_db[i].mask);
        printf("%13s | %13s | %13s | %13s | %5s | %19ld | %6s | %5u |\n", 
                get_ipstr(ls_db[i].source_router_id),
                get_ipstr(ls_db[i].neighbor_router_id),
                get_ipstr(ls_db[i].subnet),
                get_ipstr(ls_db[i].mask),
                ls_db[i].interface,
               ls_db[i].last_update_time,
               ls_db[i].state ? "Valid" : "Invalid",
               ls_db[i].color);
    }

    printf("-------------------------------------------------------------\n");
}


void print_routing_table(struct sr_rt* current) {
    // struct sr_rt* current = rt;
    printf("\nRouting Table:\n\n");
    printf("|%-16s | %-16s | %-16s | %-16s |\n", 
           "Destination", "Gateway", "Mask", "Interface");
    printf("--------------------------------------------------------------------------------------\n");
    
    while (current != NULL) {

        // Print the entry
        printf("|%-16s | %-16s | %-16s | %-16s |\n", 
               get_ipstr(current->dest.s_addr), 
               get_ipstr(current->gw.s_addr), 
               get_ipstr(current->mask.s_addr), 
               current->interface);
        // Move to the next entry
        current = current->next;
    }
}

// void send_pwospf_lsu2(struct sr_instance *sr, struct pwospf_if *pw_iface) {
//     struct pwospf_router *router = sr->ospf_subsys->router;
//     struct pwospf_if* interfaces = router->interfaces;
//     // advertisement_t *ads = (advertisement_t *)malloc(MAX_ADS * sizeof(advertisement_t));
//     advertisement_t *ads = (advertisement_t *)malloc(sizeof(advertisement_t));
//     advertisement_t *ads2 = (advertisement_t *)malloc(sizeof(advertisement_t));
//     advertisement_t *ads3 = (advertisement_t *)malloc(sizeof(advertisement_t));
//     // advertisement_t *ads = (advertisement_t *)malloc(sizeof(advertisement_t));

//     int num_ads = 0;
//     ads[0].subnet = htonl(interfaces->iface->ip & interfaces->iface->mask);
//     ads[0].mask = htonl(interfaces->iface->mask);
//     ads[0].router_id = htonl(interfaces->neighbor_id);
    
//     interfaces = interfaces->next;
//     ads2[0].subnet = htonl(interfaces->iface->ip & interfaces->iface->mask);
//     ads2[0].mask = htonl(interfaces->iface->mask);
//     ads2[0].router_id = htonl(interfaces->neighbor_id);

    
//     interfaces = interfaces->next;
//     ads3[0].subnet = htonl(interfaces->iface->ip & interfaces->iface->mask);
//     ads3[0].mask = htonl(interfaces->iface->mask);
//     ads3[0].router_id = htonl(interfaces->neighbor_id);

//     num_ads = 4;
    
//     // while (interfaces) {
//     //     ads[num_ads].subnet = htonl(interfaces->iface->ip & interfaces->iface->mask);
//     //     ads[num_ads].mask = htonl(interfaces->iface->mask);
//     //     ads[num_ads].router_id = htonl(interfaces->neighbor_id);
//     //     num_ads++;
//     //     interfaces = interfaces->next;
//     // }
//     unsigned int lsu_len = sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t) + sizeof(advertisement_t) + sizeof(advertisement_t) + 2*sizeof(advertisement_t);
//     // unsigned int lsu_len = sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t) + sizeof(advertisement_t) + sizeof(advertisement_t);
//     // unsigned int lsu_len = sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t) + sizeof(advertisement_t);
//     uint8_t *lsu_packet = (uint8_t *)malloc(lsu_len);
//     memset(lsu_packet, 0, lsu_len);

//     pwospf_hdr_t *pwospf_hdr = (pwospf_hdr_t *)lsu_packet;
//     pwospf_hdr->version = PWOSPF_VERSION;
//     pwospf_hdr->type = PWOSPF_TYPE_LSU;
//     pwospf_hdr->packet_length = htons(lsu_len);
//     pwospf_hdr->router_id = (router->router_id);
//     // pwospf_hdr->area_id = htonl(PWOSPF_AREA_ID);
//     // pwospf_hdr->checksum = 0; // Placeholder
//     // pwospf_hdr->autype = htons(PWOSPF_AU_TYPE);
//     // pwospf_hdr->authentication = 0;

//     // lsu_hdr_t *lsu_hdr = (lsu_hdr_t *)(lsu_packet + sizeof(pwospf_hdr_t));
//     // lsu_hdr->sequence = htonl(router->sequence_number++);
//     // lsu_hdr->ttl = DEFAULT_LSU_TTL;
//     // lsu_hdr->num_ads = htonl(num_ads);

//     lsu_hdr_t *lsu_hdr = (lsu_hdr_t *)(lsu_packet + sizeof(pwospf_hdr_t));
//     lsu_hdr->sequence = htons(router->sequence_number++);
//     lsu_hdr->ttl = DEFAULT_LSU_TTL;
//     lsu_hdr->num_ads = num_ads;

//     memcpy(lsu_packet + sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t), ads, sizeof(advertisement_t));
//     memcpy(lsu_packet + sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t) + sizeof(advertisement_t), ads2, sizeof(advertisement_t));
//     memcpy(lsu_packet + sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t) + sizeof(advertisement_t) + sizeof(advertisement_t), ads3, sizeof(advertisement_t));

//     printf("Adv pack size: %d\n", sizeof(advertisement_t));

//     // int checksum_len = lsu_len - sizeof(pwospf_hdr->authentication);
//     // pwospf_hdr->checksum = get_checksum((uint16_t *)lsu_packet, checksum_len / 2);

//     unsigned int ip_len = sizeof(struct ip) + lsu_len;
//     uint8_t *ip_packet = (uint8_t *)malloc(ip_len);
//     memset(ip_packet, 0, ip_len);

//     struct ip *ip_hdr = (struct ip *)ip_packet;
//     ip_hdr->ip_hl = 5;
//     ip_hdr->ip_v = 4;
//     ip_hdr->ip_tos = 0;
//     ip_hdr->ip_len = htons(ip_len);
//     ip_hdr->ip_id = htons(0);
//     ip_hdr->ip_off = htons(IP_DF);
//     ip_hdr->ip_ttl = 64;
//     ip_hdr->ip_p = OSPF_PROTOCOL_NUMBER;
//     ip_hdr->ip_src.s_addr = pw_iface->iface->ip;
//     ip_hdr->ip_dst.s_addr = pw_iface->neighbor_ip;

//     ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, ip_hdr->ip_hl * 2);//Verify if you need this in htons
//     memcpy(ip_packet + sizeof(struct ip), lsu_packet, lsu_len);

//     unsigned int ether_len = sizeof(struct sr_ethernet_hdr) + ip_len;
//     uint8_t *ether_frame = (uint8_t *)malloc(ether_len);
//     memset(ether_frame, 0, ether_len);

//     struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)ether_frame;
//     eth_hdr->ether_dhost[0] = 0x01;
//     eth_hdr->ether_dhost[1] = 0x00;
//     eth_hdr->ether_dhost[2] = 0x5e;
//     eth_hdr->ether_dhost[3] = 0x00;
//     eth_hdr->ether_dhost[4] = 0x00;
//     eth_hdr->ether_dhost[5] = 0x05;

//     memcpy(eth_hdr->ether_shost, pw_iface->iface->addr, ETHER_ADDR_LEN);
//     eth_hdr->ether_type = htons(ETHERTYPE_IP);

//     memcpy(ether_frame + sizeof(struct sr_ethernet_hdr), ip_packet, ip_len);

//     sr_send_packet(sr, ether_frame, ether_len, pw_iface->iface->name);

//     free(ip_packet);
//     free(ether_frame);
    
// };
    // pthread_mutex_lock(&sr->ospf_subsys->lock); // Ensure thread safety

    // Count the number of valid interfaces (advertisements)

    // Allocate memory for the LSU packet

    // Construct LSU header
    // Add advertisements from interfaces
