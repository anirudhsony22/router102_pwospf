/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 * #693354266
 * 
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>



#include "sr_if.h"
#include "sr_rt.h"
#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"

#include "sr_utils.c"
#include "hello.c"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/


void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    initialize_variables();
    // if (sr->if_list) {
    //     printf("Interface Found\n");
    //     sr->ospf_subsys->router->router_id = sr->if_list->ip;
    // } else {
    //     printf("No interface\n");
    //     sr->ospf_subsys->router->router_id = 0; /* Invalid ID */
    // }

    pthread_t tid;
    int thread_status;

    thread_status = pthread_create(&tid, NULL, ipcache_thread, sr);
    if (thread_status != 0) {
        perror("ipcache thread create failed");
    }

    thread_status = pthread_create(&tid, NULL, populate_pwospf, sr);
    if (thread_status != 0) {
        perror("populate_pwospf thread create failed");
    }
} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void print_incoming_packet_stats(uint8_t* packet, char* interface) {
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

        if (ntohs(arp_hdr->ar_op) == ARP_REQUEST) {
            printf("*** Incoming packet *** Type: ARP REQUEST IFACE: %s", interface);
        } else {
            printf("*** Incoming packet *** Type: ARP REPLY IFACE: %s", interface);
        }

        printf("  Source IP: ");
        print_ip_address(arp_hdr->ar_sip);
        printf("  Target IP: ");
        print_ip_address(arp_hdr->ar_tip);        
    } else {
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
        printf("*** Incoming packet *** Type: IP IFACE: %s", interface);
        printf("  Source IP: ");
        print_ip_address(ip_hdr->ip_src.s_addr);
        printf("  Target IP: ");
        print_ip_address(ip_hdr->ip_dst.s_addr);
    }

    printf(" Source MAC: ");
    print_mac_address("", eth_hdr->ether_shost);
    printf(" Dest MAC: ");
    print_mac_address("", eth_hdr->ether_dhost);

    printf("\n");
}

int is_hello(uint8_t *packet, size_t len) {
    printf("############Indide Hello 1\n");
    printf("%d %d %d %d\n\n\n", len, sizeof(struct sr_ethernet_hdr), sizeof(struct ip), sizeof(pwospf_hdr_t));
    if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(pwospf_hdr_t)) {
        return 0; // Not a valid PWOSPF Hello packet
    }
    printf("############Indide Hello 2\n");
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
        return 0; // Not an IP packet
    }
    printf("############Indide Hello 3\n");
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    if (ip_hdr->ip_p != OSPF_PROTOCOL_NUMBER) {
        return 0; // Not an OSPF packet
    }
    printf("############Indide Hello 4\n");
    pwospf_hdr_t *pwospf_hdr = (pwospf_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    if (pwospf_hdr->version != PWOSPF_VERSION || pwospf_hdr->type != PWOSPF_TYPE_HELLO) {
        return 0; // Not a PWOSPF Hello packet
    }
    // // Verify checksum (optional, for additional validation)
    // uint16_t computed_checksum = get_checksum((uint16_t *)pwospf_hdr, (pwospf_hdr->packet_length - sizeof(pwospf_hdr->authentication)) / 2);
    // if (computed_checksum != pwospf_hdr->checksum) {
    //     return 0;
    // }
    return 1;
}

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */

    assert(sr);
    assert(packet);
    assert(interface);
    print_incoming_packet_stats(packet, interface);
    if (!is_valid_ethernet_packet(len)) {
        print_drop();
        return;
    }

    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;

    switch (ntohs(eth_hdr->ether_type)) {
        case ETHERTYPE_ARP:
            handle_arp(sr, packet, len, interface);
            break;
        case ETHERTYPE_IP:
            printf("IP Rec'd\n");
            if (!is_valid_ip_packet(packet)) // also decreasing ttl
            {
                print_drop();
                return;
            }
            if(is_hello(packet, len)){
                printf("!!!!!!!!!!!!!!!!!!!!!#########################FFFFFFFFFFF Rec'd Hello **************************************\n");
            }
            else{
                populate_ip_header(packet);
                handle_ip(packet, sr, len, interface);
            }

            break;
        default:
            printf("Received an unknown packet type: 0x%04x\n", ntohs(eth_hdr->ether_type));
            print_drop();
    }
}