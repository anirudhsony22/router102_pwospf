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

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>


/* Function prototypes */
int pwospf_init(struct sr_instance* sr);
void pwospf_lock(struct pwospf_subsys* subsys);
void pwospf_unlock(struct pwospf_subsys* subsys);
void send_pwospf_hello(struct sr_instance *sr, struct pwospf_if *pw_iface);
static
void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    struct pwospf_router* router = sr->ospf_subsys->router;

    while(1)
    {
        printf("pwospf subsystem awake\n");
        /* Lock the PWOSPF subsystem */
        pwospf_lock(sr->ospf_subsys);
        /* Iterate over all PWOSPF interfaces and send Hello packets */
        struct pwospf_if* pw_iface = router->interfaces;
        while (pw_iface) {
            printf("Interface\n");
            /* Send Hello packet on this interface */
            send_pwospf_hello(sr, pw_iface);
            /* Update last_hello_time to current time */
            pw_iface->last_hello_time = time(NULL);
            pw_iface = pw_iface->next;
        }
        /* Unlock the PWOSPF subsystem */
        pwospf_unlock(sr->ospf_subsys);
        /* Sleep for the Hello interval */
        printf("pwospf subsystem sleeping\n");
        sleep(HELLO_INTERVAL/2); /* 10 seconds as defined earlier */
    };
    return NULL;
} /* -- run_ospf_thread -- */

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
    printf("PWOSPF Init\n");

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

    /* Set Router ID to IP address of the first interface */
    if (sr->if_list) {
        printf("Interface Found\n");
        sr->ospf_subsys->router->router_id = sr->if_list->ip;
    } else {
        printf("No interface\n");
        sr->ospf_subsys->router->router_id = 0; /* Invalid ID */
        return 0;
    }

    /* Initialize PWOSPF interfaces */
    struct sr_if* iface = sr->if_list;
    struct pwospf_if* prev_pw_iface = NULL;
    printf("Setting up ifs\n");
    int cnt = 0;
    while (iface) {
        printf("Setting the interfaces\n");
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

    /* -- start thread subsystem -- */
    printf("Creating thread for hello packet\n");
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        /* Handle cleanup */
        /* Free interfaces */
        struct pwospf_if* current = sr->ospf_subsys->router->interfaces;
        while (current) {
            struct pwospf_if* temp = current;
            current = current->next;
            free(temp);
        }
        free(sr->ospf_subsys->router);
        free(sr->ospf_subsys);
        return 0;
    }

    return cnt < 3 ? 0 : 1; /* success */
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
} /* -- pwospf_lock -- */

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
} /* -- pwospf_unlock -- */

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
    pwospf_hdr->router_id = (pw_iface->iface->ip);    /* Router ID is the interface IP */
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
    sr_send_packet(sr, ether_frame, ether_len, pw_iface->iface->name);
    // printf("Send Hello Initiated 10\n");
    
    /* Clean up */
    free(pwospf_packet);
    free(ip_packet);
    free(ether_frame);
}

void* populate_pwospf(void* sr_arg) {
    struct sr_instance *sr = sr_arg;

    while (1) {
        printf("pwospf_init Thread is running...\n");
        int all_good = pwospf_init(sr);

        if (all_good == 1) {
            printf("############################ #ALLGOOD ##########################\n\n");
            break;
        }
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