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
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

pthread_mutex_t PW_LOCK = PTHREAD_MUTEX_INITIALIZER;
/* Function prototypes */
int pwospf_init(struct sr_instance* sr);
// void pwospf_lock(struct pwospf_subsys* subsys);
// void pwospf_unlock(struct pwospf_subsys* subsys);
void send_pwospf_hello(struct sr_instance *sr, struct pwospf_if *pw_iface);
static
void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    struct pwospf_router* router = sr->ospf_subsys->router;
    int counter=0;

    while(1)
    {
        printf("pwospf subsystem awake\n");
        /* Lock the PWOSPF subsystem */
        // pthread_mutex_lock(&sr->ospf_subsys->lock);
        pthread_mutex_lock(&PW_LOCK);
        /* Iterate over all PWOSPF interfaces and send Hello packets */
        struct pwospf_if* pw_iface = router->interfaces;
        while (pw_iface) {
            /* Send Hello packet on this interface */
            // printf("Trying to send Hello Packet %s\n", pw_iface->iface->name);
            send_pwospf_hello(sr, pw_iface);
            // printf("Sent Hello Packet %s\n", pw_iface->iface->name);
            /* Update last_hello_time to current time */
            pw_iface->last_hello_time = time(NULL);
            pw_iface = pw_iface->next;
        }
        invalidate_expired_links(sr->ospf_subsys->router->router_id, 12, sr);
        // invalidate_expired_links(&sr->database, sr->rid, HELLO_TIMEOUT/5);
        /* Unlock the PWOSPF subsystem */
        // printf("After UnLock");
        /* Sleep for the Hello interval */
        // printf("pwospf subsystem sleeping\n");
        // print_link_state_table();
        if(counter%2==0){
            send_pwospf_lsu(sr);
        }
        counter++;
        // printf("Counter: %d\n", counter);
        pthread_mutex_unlock(&PW_LOCK);
        // pthread_mutex_unlock(&sr->ospf_subsys->lock);
        // print_routing_table(sr);
        print_link_state_table();
        sleep(HELLO_INTERVAL); /* 10 seconds as defined earlier */
    };
    printf("#############################Exitted While1\n");
    return NULL;
} /* -- run_ospf_thread -- */

void print_ip(uint32_t ip) {
    ip=htonl(ip);
    printf("%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}
void print_link_state_table() {
    printf("-------------------------------------------------------------\n");
    printf("| Source Router | Neighbor Router | Subnet       | Mask       | Last Hello Time       | State  | Color |\n");
    printf("-------------------------------------------------------------\n");

    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
        // if (ls_db[i].state == 0 && ls_db[i].source_router_id == 0) continue; // Skip empty or invalid entries
        print_ip(ls_db[i].source_router_id);
        printf(" | ");
        print_ip(ls_db[i].neighbor_router_id);
        printf(" | ");
        print_ip(ls_db[i].subnet);
        printf(" | ");
        print_ip(ls_db[i].mask);
        printf(" | %19ld | %6s | %5u |\n", 
               ls_db[i].last_hello_time,
               ls_db[i].state ? "Valid" : "Invalid",
               ls_db[i].color);
    }
    printf("-------------------------------------------------------------\n");
}
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
    // printf("PWOSPF Init\n");

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct pwospf_subsys));
    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    /* Allocate memory for PWOSPF router */
    sr->ospf_subsys->router = malloc(sizeof(struct pwospf_router));
    if (!sr->ospf_subsys->router) {
        fprintf(stderr, "Failed to allocate memory for PWOSPF router\n");
        free(sr->ospf_subsys);
        return 0; /* Return error */
    }
    pthread_mutex_init(&sr->ospf_subsys->router->lock, NULL);

    /* Initialize PWOSPF router fields */
    sr->ospf_subsys->router->area_id = PWOSPF_AREA_ID;
    sr->ospf_subsys->router->lsuint = 30; /* Default 30 seconds */
    sr->ospf_subsys->router->interfaces = NULL;
    sr->ospf_subsys->router->sequence_number = 0;


    /* Set Router ID to IP address of the first interface */
    if (sr->if_list) {
        // printf("Interface Found\n");
        sr->ospf_subsys->router->router_id = sr->if_list->ip;
    } else {
        printf("No interface\n");
        sr->ospf_subsys->router->router_id = 0; /* Invalid ID */
        return 0;
    }

    /* Initialize PWOSPF interfaces */
    struct sr_if* iface = sr->if_list;
    struct pwospf_if* prev_pw_iface = NULL;
    // printf("Setting up ifs\n");
    int cnt = 0;
    while (iface) {
        // printf("Setting the interfaces\n");
        /* Allocate memory for PWOSPF interface */
        struct pwospf_if* pw_iface = malloc(sizeof(struct pwospf_if));
        if (!pw_iface) {
            fprintf(stderr, "Failed to allocate memory for PWOSPF interface\n");
            /* Handle cleanup if necessary */
            free(sr->ospf_subsys->router);
            free(sr->ospf_subsys);
            return 0;
        }

        /* Initialize PWOSPF interface fields */
        pw_iface->iface = iface;
        pw_iface->helloint = HELLO_INTERVAL; /* Default 10 seconds */
        pw_iface->neighbor_id = 0;            /* No neighbor yet */
        pw_iface->neighbor_ip = 0;
        pw_iface->last_hello_time = 0;
        pw_iface->next = NULL;

        /* Add to the router's interface list */
        if (prev_pw_iface) {
            prev_pw_iface->next = pw_iface;
        } else {
            sr->ospf_subsys->router->interfaces = pw_iface;
        }
        prev_pw_iface = pw_iface;

        iface = iface->next;
        cnt++;
    }

    return cnt < 3 ? 0 : 1; /* success */
} /* -- pwospf_init -- */

/* Set the Router ID */
void sr_set_rid(struct sr_instance *sr) {
    assert(sr);
    if (sr->if_list) {
        sr->rid = sr->if_list->addr; // Use IP of the first interface
        printf("Router ID (RID) set to: %u\n", sr->rid);
    } else {
        sr->rid = 0; // Invalid RID
        printf("No interfaces available. RID set to 0.\n");
    }
}
/* Initialize the link state database (lsdb) */
// void init_lsdb(lsdb_t *lsdb) {
//     lsdb->count = 0;
//     for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
//         lsdb->entries[i].state = 0; // Mark all entries as invalid
//     }
//     printf("Link State Database initialized.\n");
// }
/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

// void pwospf_lock(struct pwospf_subsys* subsys)
// {
//     if ( pthread_mutex_lock(&subsys->lock) )
//     { assert(0); }
// } /* -- pwospf_lock -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

// void pwospf_unlock(struct pwospf_subsys* subsys)
// {
//     if ( pthread_mutex_unlock(&subsys->lock) )
//     { assert(0); }
// } /* -- pwospf_unlock -- */

/*---------------------------------------------------------------------
 * Method: send_pwospf_hello
 *
 * Constructs and sends a PWOSPF Hello packet on the specified interface.
 *
 *---------------------------------------------------------------------*/
void send_pwospf_hello(struct sr_instance *sr, struct pwospf_if *pw_iface) {
    // printf("Send Hello Initiated\n");
    /* Total PWOSPF packet length */
    unsigned int pwospf_len = sizeof(pwospf_hdr_t) + sizeof(pwospf_hello_t);
    
    /* Allocate memory for the PWOSPF packet */
    uint8_t *pwospf_packet = (uint8_t *)malloc(pwospf_len);
    if (!pwospf_packet) {
        fprintf(stderr, "Memory allocation failed for PWOSPF packet\n");
        return;
    }
    // printf("Send Hello Initiated 2\n");
    memset(pwospf_packet, 0, pwospf_len);
    
    /* PWOSPF Header */
    pwospf_hdr_t *pwospf_hdr = (pwospf_hdr_t *)pwospf_packet;
    pwospf_hdr->version = PWOSPF_VERSION;
    pwospf_hdr->type = PWOSPF_TYPE_HELLO;
    pwospf_hdr->packet_length = htons(pwospf_len);
    pwospf_hdr->router_id = sr->ospf_subsys->router->router_id;
    pwospf_hdr->area_id = htonl(PWOSPF_AREA_ID);
    pwospf_hdr->checksum = 0;             /* Initialize checksum to zero */
    pwospf_hdr->autype = htons(PWOSPF_AU_TYPE);
    pwospf_hdr->authentication = 0;       /* Authentication is 0 */
    
    /* PWOSPF Hello Packet */
    pwospf_hello_t *pwospf_hello = (pwospf_hello_t *)(pwospf_packet + sizeof(pwospf_hdr_t));
    pwospf_hello->network_mask = pw_iface->iface->mask;
    pwospf_hello->hello_int = htons(pw_iface->helloint);
    pwospf_hello->padding = 0;
    
    /* Compute the checksum */
    /* Exclude the Authentication field (last 8 bytes) */
    // printf("Send Hello Initiated 3\n");
    int checksum_len = pwospf_len - sizeof(pwospf_hdr->authentication);
    pwospf_hdr->checksum = get_checksum((uint16_t *)pwospf_packet, checksum_len / 2);
    
    /* Now create the IP header */
    unsigned int ip_len = sizeof(struct ip) + pwospf_len;
    uint8_t *ip_packet = (uint8_t *)malloc(ip_len);
    // printf("Send Hello Initiated 4\n");
    if (!ip_packet) {
        fprintf(stderr, "Memory allocation failed for IP packet\n");
        free(pwospf_packet);
        return;
    }
    memset(ip_packet, 0, ip_len);
    // printf("Send Hello Initiated 5\n");
    struct ip *ip_hdr = (struct ip *)ip_packet;
    ip_hdr->ip_hl = 5;  /* IP header length (5 * 4 = 20 bytes) */
    ip_hdr->ip_v = 4;   /* IP version 4 */
    ip_hdr->ip_tos = 0; /* Type of service */
    ip_hdr->ip_len = htons(ip_len); /* Total packet length */
    ip_hdr->ip_id = htons(0); /* ID of this packet */
    ip_hdr->ip_off = htons(IP_DF); /* Fragment offset */
    ip_hdr->ip_ttl = 64; /* Time to live */
    ip_hdr->ip_p = OSPF_PROTOCOL_NUMBER; /* Protocol number for OSPF */
    ip_hdr->ip_src.s_addr = (pw_iface->iface->ip); /* Source IP */
    ip_hdr->ip_dst.s_addr = (ALLSPFROUTERS); /* Destination IP (224.0.0.5) */ //Big Endian
    
    /* Compute IP checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, ip_hdr->ip_hl * 2);
    // printf("Send Hello Initiated 6\n");
    /* Copy PWOSPF packet into IP payload */
    memcpy(ip_packet + sizeof(struct ip), pwospf_packet, pwospf_len);
    
    /* Now create the Ethernet header */
    unsigned int ether_len = sizeof(struct sr_ethernet_hdr) + ip_len;
    uint8_t *ether_frame = (uint8_t *)malloc(ether_len);
    // printf("Send Hello Initiated 7\n");
    if (!ether_frame) {
        fprintf(stderr, "Memory allocation failed for Ethernet frame\n");
        free(pwospf_packet);
        free(ip_packet);
        return;
    }
    // printf("Send Hello Initiated 8\n");
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
    memcpy(eth_hdr->ether_shost, pw_iface->iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ETHERTYPE_IP); /* Ethernet type for IP */
    
    /* Copy IP packet into Ethernet frame */
    memcpy(ether_frame + sizeof(struct sr_ethernet_hdr), ip_packet, ip_len);
    
    // printf("Send Hello Initiated 9\n");
    /* Send the packet */
    // printf("####################At VNS Function Send\n");
    sr_send_packet(sr, ether_frame, ether_len, pw_iface->iface->name);
    // printf("Send Hello Initiated 10\n");
    
    /* Clean up */
    free(pwospf_packet);
    free(ip_packet);
    free(ether_frame);
}

void send_pwospf_lsu(struct sr_instance *sr) {
    // printf("Sending LSU packets based on router interfaces\n");

    // Validate the router and its interfaces
    struct pwospf_router *router = sr->ospf_subsys->router;
    if (!router) {
        fprintf(stderr, "Router information not available\n");
        return;
    }

    // pthread_mutex_lock(&sr->ospf_subsys->lock); // Ensure thread safety

    // Count the number of valid interfaces (advertisements)
    int num_ads = 0;
    struct pwospf_if *pw_iface = router->interfaces;
    while (pw_iface) {
        num_ads++;
        pw_iface = pw_iface->next;
    }

    // Allocate memory for the LSU packet
    unsigned int lsu_len = sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t) + num_ads * sizeof(lsu_adv_t);
    uint8_t *lsu_packet = (uint8_t *)malloc(lsu_len);
    if (!lsu_packet) {
        fprintf(stderr, "Memory allocation failed for LSU packet\n");
        // pthread_mutex_unlock(&sr->ospf_subsys->lock);
        return;
    }
    memset(lsu_packet, 0, lsu_len);

    // Construct PWOSPF header
    pwospf_hdr_t *pwospf_hdr = (pwospf_hdr_t *)lsu_packet;
    pwospf_hdr->version = PWOSPF_VERSION;
    pwospf_hdr->type = PWOSPF_TYPE_LSU;
    pwospf_hdr->packet_length = htons(lsu_len);
    pwospf_hdr->router_id = router->router_id;
    pwospf_hdr->area_id = htonl(PWOSPF_AREA_ID);
    pwospf_hdr->checksum = 0; // Placeholder
    pwospf_hdr->autype = htons(PWOSPF_AU_TYPE);
    pwospf_hdr->authentication = 0;

    // Construct LSU header
    lsu_hdr_t *lsu_hdr = (lsu_hdr_t *)(lsu_packet + sizeof(pwospf_hdr_t));
    lsu_hdr->sequence = router->sequence_number++;
    // printf("Send side Sequence: %d\n",lsu_hdr->sequence);
    lsu_hdr->ttl = DEFAULT_LSU_TTL;
    lsu_hdr->num_ads = num_ads;

    // Add advertisements from interfaces
    lsu_adv_t *advertisements = (lsu_adv_t *)(lsu_packet + sizeof(pwospf_hdr_t) + sizeof(lsu_hdr_t));
    pw_iface = router->interfaces;
    int ad_index = 0;
    while (pw_iface) {
        advertisements[ad_index].subnet = pw_iface->iface->ip & pw_iface->iface->mask; // Subnet calculation
        advertisements[ad_index].mask = pw_iface->iface->mask;
        advertisements[ad_index].router_id = pw_iface->neighbor_id; // Neighbor router ID
        ad_index++;
        pw_iface = pw_iface->next;
    }

    // Compute checksum
    int checksum_len = lsu_len - sizeof(pwospf_hdr->authentication);
    pwospf_hdr->checksum = get_checksum((uint16_t *)lsu_packet, checksum_len / 2);

    // Send LSU to each neighbor
    pw_iface = router->interfaces;

    while (pw_iface) {
        // Create IP and Ethernet headers for each neighbor
        unsigned int ip_len = sizeof(struct ip) + lsu_len;
        uint8_t *ip_packet = (uint8_t *)malloc(ip_len);
        if (!ip_packet) {
            fprintf(stderr, "Memory allocation failed for IP packet\n");
            free(lsu_packet);
            // pthread_mutex_unlock(&sr->ospf_subsys->lock);
            return;
        }
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
        ip_hdr->ip_src.s_addr = pw_iface->iface->ip;
        ip_hdr->ip_dst.s_addr = pw_iface->neighbor_ip; // Direct neighbor's IP

        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = get_checksum((uint16_t *)ip_hdr, ip_hdr->ip_hl * 2);

        // Copy LSU packet into IP payload
        memcpy(ip_packet + sizeof(struct ip), lsu_packet, lsu_len);

        unsigned int ether_len = sizeof(struct sr_ethernet_hdr) + ip_len;
        uint8_t *ether_frame = (uint8_t *)malloc(ether_len);
        if (!ether_frame) {
            fprintf(stderr, "Memory allocation failed for Ethernet frame\n");
            free(lsu_packet);
            free(ip_packet);
            // pthread_mutex_unlock(&sr->ospf_subsys->lock);
            return;
        }
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
        memcpy(eth_hdr->ether_shost, pw_iface->iface->addr, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ETHERTYPE_IP); /* Ethernet type for IP */
        
        /* Copy IP packet into Ethernet frame */
        memcpy(ether_frame + sizeof(struct sr_ethernet_hdr), ip_packet, ip_len);

        // print_all_headers(eth_hdr, ip_hdr, pwospf_hdr, lsu_hdr, advertisements, num_ads);
        // Send the Ethernet frame
        sr_send_packet(sr, ether_frame, ether_len, pw_iface->iface->name);

        // Clean up
        free(ip_packet);
        free(ether_frame);

        pw_iface = pw_iface->next;
    }

    free(lsu_packet);
    // pthread_mutex_unlock(&sr->ospf_subsys->lock);
}

void create_hello_thread(struct sr_instance *sr){
    /* -- start thread subsystem -- */
    printf("Creating thread for hello packet\n");
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        /* Handle cleanup */
        /* Free interfaces */
        struct pwospf_if* current = sr->ospf_subsys->router->interfaces;
        printf("Freeing up space in thread started\n");
        while (current) {
            struct pwospf_if* temp = current;
            current = current->next;
            free(temp);
        }
        free(sr->ospf_subsys->router);
        free(sr->ospf_subsys);
        return 0;
    }
}

void* populate_pwospf(void* sr_arg) {
    struct sr_instance *sr = sr_arg;

    while (1) {
        // printf("pwospf_init Thread is running...\n");
        int all_good = pwospf_init(sr);

        if (all_good == 1) {
            // printf("All Good################");
            create_hello_thread(sr);
            struct sr_if* iface = sr->if_list;
            uint32_t source_router_id = sr->ospf_subsys->router->router_id;
            while (iface) {
                update_lsdb(source_router_id, 0, iface->ip & iface->mask, iface->mask, 1, iface->name);
                // printf("Update IFACE\n");
                iface = iface->next;
            }
            break;
        }
        // build_routing_table_in_place(sr->ospf_subsys->router->router_id);
        create_routing_table(sr->ospf_subsys->router->router_id);
        // print_routing_table(dynamic_routing_table, 6);
        sleep(1);
    }
    return NULL;
}

void handle_hello(struct sr_instance *sr,
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

void update_lsdb(uint32_t source_id, uint32_t neighbor_id, uint32_t subnet, uint32_t mask, int is_current_id, char *ifname) {
    // printf("Entered Update LSDB\n");
    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
        if (ls_db[i].source_router_id == source_id && (ls_db[i].subnet == subnet)) {
            if(ls_db[i].neighbor_router_id==0 && is_current_id==1){
                //Todo: Send LSU
            }
            ls_db[i].neighbor_router_id = neighbor_id;
            ls_db[i].subnet = subnet;
            ls_db[i].last_hello_time = time(NULL); // Update timer
            ls_db[i].mask = mask;
            ls_db[i].state = 1;
            strncpy(ls_db[i].interface, ifname, SR_IFACE_NAMELEN);
            // ls_db[i].interface[SR_IFACE_NAMELEN - 1] = '\0'; // Ensure null termination
            // printf("Updated hahaha\n");
            return;
        }
    }
    // printf("No mathcing entry, hence creating new one\n");
    for (int i=0; i<MAX_LINK_STATE_ENTRIES; i++){
        // printf("The state: %d \n\n",ls_db[i].state);
        if(ls_db[i].state==0){
            ls_db[i].source_router_id = source_id;
            ls_db[i].neighbor_router_id = neighbor_id;
            ls_db[i].subnet = subnet;
            ls_db[i].last_hello_time = time(NULL); // Update timer
            ls_db[i].mask = mask;
            ls_db[i].state = 1;
            // printf("Updated hahaha\n");
            return;
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

void init_lsdb(){
    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++){
        ls_db[i].state = 0;
    }
}

void invalidate_expired_links(uint32_t current_router_id, time_t timeout, struct sr_instance *sr) {
    time_t now = time(NULL);
    // printf("In the invalidate loop\n");
    // print_ip_address(ntohl(current_router_id));
    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
        if (ls_db[i].state == 1 && 
            (ls_db[i].source_router_id == current_router_id) && 
            (now - ls_db[i].last_hello_time > timeout) &&
            ls_db[i].neighbor_router_id != 0) {

            uint32_t prev_id = ls_db[i].neighbor_router_id;
            ls_db[i].neighbor_router_id = 0;

            printf("Invalidating the links of router: \n");
            send_pwospf_lsu(sr);
            //Todo: Send LSU
            // print_ip(ls_db[i].source_router_id);
            // printf("neighbor id: \n");
            // print_ip(prev_id);
            // printf("\n");
        }
    }
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

void print_sequence_table(sequence_table_entry_t *seq, int size) {
    printf("Sequence Table:\n");
    printf("--------------------------------------------------\n");
    printf("| Source Router ID     | Last Sequence Number    |\n");
    printf("--------------------------------------------------\n");
    for (int i = 0; i < size; i++) {
        printf("| %-20u | %-22u |\n", seq[i].source_router_id, seq[i].last_sequence_num);
    }
    printf("--------------------------------------------------\n");
}


void print_lsu_packet(lsu_hdr_t *lsu_h, lsu_adv_t *lsu_a, uint32_t num_advertisements) {
    printf("LSU Header:\n");
    printf("----------------------------------------\n");
    printf("Sequence Number: %u\n", ntohl(lsu_h->sequence));
    printf("TTL: %u\n", lsu_h->ttl);
    printf("Number of Advertisements: %u\n", ntohl(lsu_h->num_ads));
    printf("----------------------------------------\n");

    // Print each advertisement
    printf("LSU Advertisements:\n");
    for (uint32_t i = 0; i < num_advertisements; i++) {
        printf("  Advertisement %u:\n", i + 1);
        printf("    Subnet: ");
        print_ip(lsu_a[i].subnet);
        printf("\n    Mask: ");
        print_ip(lsu_a[i].mask);
        printf("\n    Router ID: ");
        print_ip(lsu_a[i].router_id);
        printf("\n");
    }
}

void print_all_headers(struct sr_ethernet_hdr *eth_hdr, struct ip *ip_hdr, 
                       pwospf_hdr_t *pwospf_hdr, lsu_hdr_t *lsu_hdr, 
                       lsu_adv_t *advertisements, int num_ads) {
    printf("\n--- Ethernet Header ---\n");
    printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
           eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
    printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
           eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("  EtherType: 0x%04x\n", ntohs(eth_hdr->ether_type));

    printf("\n--- IP Header ---\n");
    printf("  Version: %d\n", ip_hdr->ip_v);
    printf("  Header Length: %d bytes\n", ip_hdr->ip_hl * 4);
    printf("  Total Length: %d bytes\n", ntohs(ip_hdr->ip_len));
    printf("  Protocol: %d\n", ip_hdr->ip_p);
    printf("  Source IP: ");
    print_ip(ntohl(ip_hdr->ip_src.s_addr));
    printf("\n  Destination IP: ");
    print_ip(ntohl(ip_hdr->ip_dst.s_addr));
    printf("\n");

    printf("\n--- PWOSPF Header ---\n");
    printf("  Version: %d\n", pwospf_hdr->version);
    printf("  Type: %d\n", pwospf_hdr->type);
    printf("  Packet Length: %u\n", ntohs(pwospf_hdr->packet_length));
    printf("  Router ID: ");
    print_ip(pwospf_hdr->router_id);
    printf("\n  Area ID: ");
    print_ip(ntohl(pwospf_hdr->area_id));
    printf("\n  Checksum: 0x%04x\n", pwospf_hdr->checksum);
    printf("  Authentication Type: %u\n", ntohs(pwospf_hdr->autype));

    printf("\n--- LSU Header ---\n");
    printf("  Sequence Number: %u\n", lsu_hdr->sequence);
    printf("  TTL: %u\n", lsu_hdr->ttl);
    printf("  Number of Advertisements: %u\n", ntohl(lsu_hdr->num_ads));

    printf("\n--- LSU Advertisements ---\n");
    for (int i = 0; i < num_ads; i++) {
        printf("  Advertisement %d:\n", i + 1);
        printf("    Subnet: ");
        print_ip(advertisements[i].subnet);
        printf("\n    Mask: ");
        print_ip(advertisements[i].mask);
        printf("\n    Router ID: ");
        print_ip(advertisements[i].router_id);
        printf("\n");
    }
}


void add_routing_entry(uint32_t next_hop, uint32_t subnet, uint32_t mask, char *interface[SR_IFACE_NAMELEN], int *rt_index) {
    if (*rt_index < 15) {
        dynamic_routing_table[*rt_index].dest.s_addr = subnet;
        dynamic_routing_table[*rt_index].gw.s_addr = next_hop;
        dynamic_routing_table[*rt_index].mask.s_addr = mask;
        dynamic_routing_table[*rt_index].next = NULL;
        dynamic_routing_table[*rt_index].dynamic = 1;
        strncpy(dynamic_routing_table[*rt_index].interface, interface, SR_IFACE_NAMELEN);
        dynamic_routing_table[*rt_index].interface[SR_IFACE_NAMELEN - 1] = '\0';
        if (*rt_index > 0) {
            dynamic_routing_table[*rt_index - 1].next = &dynamic_routing_table[*rt_index];
        }
        (*rt_index)++;
    } else {
        printf("Routing table is full!\n");
    }
}

void create_routing_table(uint32_t my_router_id) {
    struct queue qt[MAX_LINK_STATE_ENTRIES];
    int rear = 0;
    int front = 0;
    int rt_index = 0; // Start index for routing table

    // for (int i=0;i<15;i++){
    //     dynamic_routing_table[i].used=0;
    // }
    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++){
        ls_db[i].color=WHITE;
    }

    //Add direct neighbors
    for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
        if (ls_db[i].state == 1 && 
            ls_db[i].source_router_id == my_router_id) {
            qt[rear].neighbor_router_id = ls_db[i].neighbor_router_id;
            qt[rear].subnet = ls_db[i].subnet;
            qt[rear].mask = ls_db[i].mask;
            qt[rear].next_hop = ls_db[i].neighbor_router_id;
            strncpy(qt[rear].interface, ls_db[i].interface, SR_IFACE_NAMELEN); // Copy interface name
            qt[rear].interface[SR_IFACE_NAMELEN - 1] = '\0'; // Ensure null-termination
            rear++;
            add_routing_entry(
                ls_db[i].neighbor_router_id, // Next hop is the neighbor itself
                ls_db[i].subnet,             // Subnet of the link
                ls_db[i].mask,               // Subnet mask
                ls_db[i].interface,
                &rt_index                     // Routing table index
            );
            ls_db[i].color = BLACK;
            printf("Adding link :");
            print_ip(ls_db[i].subnet);
            printf("\n");
        }
    }

    //Add others
    while(front<rear){
        //Pop the element from the queue
        uint32_t current_router_id = qt[front].neighbor_router_id;
        uint32_t next_hop = qt[front].next_hop;
        char ifname[SR_IFACE_NAMELEN];
        strncpy(ifname, qt[front].interface, SR_IFACE_NAMELEN);
        ifname[SR_IFACE_NAMELEN - 1] = '\0';

        for (int i = 0; i < MAX_LINK_STATE_ENTRIES; i++) {
            if (ls_db[i].state == 1 && ls_db[i].source_router_id == current_router_id) {
                
                //Current Subnet
                uint32_t c_sn = ls_db[i].subnet;
                int link_used = 0;

                //Check if this subnet was used before
                for (int j=0; j<MAX_LINK_STATE_ENTRIES;j++){
                    if(ls_db[j].subnet == c_sn && ls_db[j].state == 1 && ls_db[j].color==BLACK){
                        link_used=1;
                    }
                }

                //If not used, add it to our routing table
                if(link_used==0){
                    // printf("Adding link :");
                    // print_ip(ls_db[i].subnet);
                    // printf("\n");
                    qt[rear].neighbor_router_id = ls_db[i].neighbor_router_id;
                    qt[rear].subnet = ls_db[i].subnet;
                    qt[rear].mask = ls_db[i].mask;
                    qt[rear].next_hop = next_hop;
                    strncpy(qt[rear].interface, ls_db[i].interface, SR_IFACE_NAMELEN); // Safe string copy
                    qt[rear].interface[SR_IFACE_NAMELEN - 1] = '\0'; // Ensure null termination
                    ls_db[i].color = BLACK;
                    rear++;
                    add_routing_entry(
                        next_hop,
                        ls_db[i].subnet,
                        ls_db[i].mask,
                        ifname,
                        &rt_index                        
                    );
                    ls_db[i].color=BLACK;
                }
                else{
                    // printf("Link Used :");
                    // print_ip(ls_db[i].subnet);
                    // printf("\n");
                }
            }
        }
        front++;
    }
    

}


void link_static_and_dynamic_tables(struct sr_instance* sr) {
    struct sr_rt* rt_walker = sr->routing_table;
    if(rt_walker==NULL || rt_walker->dynamic==1){
        rt_walker = (struct sr_rt*)&dynamic_routing_table[0];
    }
    else{
        rt_walker->next = (struct sr_rt*)&dynamic_routing_table[0];
    }
    // if (rt_walker == NULL || rt_walker->dynamic==1) {
    //     sr->routing_table = (struct sr_rt*)&dynamic_routing_table[0];
    // } else {
    //     while (rt_walker->next && rt_walker->next->dynamic==0) {
    //         rt_walker = rt_walker->next;
    //     }
    //     rt_walker->next = (struct sr_rt*)&dynamic_routing_table[0];
    // }
}

// void print_routing_table(struct sr_rt2 table[], int size) {
//     printf("Routing Table:\n");
//     printf("|%-16s | %-16s | %-16s | %-16s |\n", "Destination", "Next Hop", "Mask", "Interface");
//     printf("--------------------------------------------------------------------------------\n");
//     for (int i = 0; i < size; i++) {
//         char dest_ip[INET_ADDRSTRLEN];
//         char gw_ip[INET_ADDRSTRLEN];
//         char mask_ip[INET_ADDRSTRLEN];

//         inet_ntop(AF_INET, &table[i].dest, dest_ip, INET_ADDRSTRLEN);
//         inet_ntop(AF_INET, &table[i].gw, gw_ip, INET_ADDRSTRLEN);
//         inet_ntop(AF_INET, &table[i].mask, mask_ip, INET_ADDRSTRLEN);

//         printf("|%-16s | %-16s | %-16s | %-16s | %-5d |\n", 
//                 dest_ip, gw_ip, mask_ip, table[i].interface);
//     }
// }


void print_routing_table(struct sr_instance* sr) {
    struct sr_rt* current = sr->routing_table;
    printf("\nRouting Table:\n\n");
    printf("|%-16s | %-16s | %-16s | %-16s | %-5s |\n", 
           "Destination", "Gateway", "Mask", "Interface", "Dynamic");
    printf("--------------------------------------------------------------------------------------\n");

    while (current != NULL) {
        char dest_ip[INET_ADDRSTRLEN];
        char gw_ip[INET_ADDRSTRLEN];
        char mask_ip[INET_ADDRSTRLEN];

        // Convert IP addresses to strings for printing
        inet_ntop(AF_INET, &current->dest, dest_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &current->gw, gw_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &current->mask, mask_ip, INET_ADDRSTRLEN);

        // Print the entry
        printf("|%-16s | %-16s | %-16s | %-16s | %-5s |\n", 
               dest_ip, 
               gw_ip, 
               mask_ip, 
               current->interface, 
               current->dynamic ? "Yes" : "No");

        // Move to the next entry
        current = current->next;
    }
}