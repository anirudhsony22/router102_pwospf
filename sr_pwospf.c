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

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>


/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);
char* get_ipstr(uint32_t ip_big_endian);
void send_pwospf_hello(struct sr_instance *sr, struct sr_if *iface);

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
                track_lsdb[track_count].mask = interfaces->iface->mask;
                strncpy(track_lsdb[track_count].interface, interfaces->iface->name, SR_IFACE_NAMELEN);
                track_count++;
            }
            interfaces = interfaces->next;
        }
        if(change1){
            printf("Change1 (Link Down) detected \n");
            //LSU Send
        }

        if (pthread_mutex_unlock(&sr->ospf_subsys->lock3)) assert(0); 
        //L3 Unlock


        if(change1){
            //L2 Lock
            if (pthread_mutex_lock(&sr->ospf_subsys->lock2)) assert(0); 
            //LSDB Update
            for(int i=0;i<track_count;i++){
                update_lsdb(track_lsdb[track_count].source_router_id,
                            track_lsdb[track_count].neighbor_router_id,
                            track_lsdb[track_count].subnet,
                            track_lsdb[track_count].mask,
                            1,
                            track_lsdb[track_count].interface);
            }

            if (pthread_mutex_unlock(&sr->ospf_subsys->lock2)) assert(0); 
            //L2 Unlock
            
            //L1 Lock
            //Routing Table Update
            //L1 Unlock
        }
        

        sleep(2);
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
    pwospf_hdr->router_id = htonl(sr->ospf_subsys->router->router_id);
    pwospf_hdr->area_id = htonl(PWOSPF_AREA_ID);
    pwospf_hdr->checksum = 0;             /* Initialize checksum to zero */
    pwospf_hdr->autype = htons(PWOSPF_AU_TYPE);
    pwospf_hdr->authentication = 0;       /* Authentication is 0 */
    
    /* PWOSPF Hello Packet */
    pwospf_hello_t *pwospf_hello = (pwospf_hello_t *)(pwospf_packet + sizeof(pwospf_hdr_t));
    pwospf_hello->network_mask = htonl(iface->mask);
    pwospf_hello->hello_int = htons(HELLO_INTERVAL);
    pwospf_hello->padding = 0;
    int checksum_len = pwospf_len - sizeof(pwospf_hdr->authentication);
    pwospf_hdr->checksum = get_checksum((uint16_t *)pwospf_packet, checksum_len / 2);
    
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
    ip_hdr->ip_src.s_addr = htonl(iface->ip); /* Source IP */
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
