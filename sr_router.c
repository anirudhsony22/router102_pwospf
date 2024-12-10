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

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/
int is_pwospf(uint8_t *packet);

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);
    initialize_variables();

    pthread_t tid;
    int thread_status;

    thread_status = pthread_create(&tid, NULL, ipcache_thread, sr);
    if (thread_status != 0) {
        perror("ipcache thread create failed");
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
void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */

    assert(sr);
    assert(packet);
    assert(interface);

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
            if (!is_valid_ip_packet(packet)) // also decreasing ttl
            {
                print_drop();
                return;
            }
            if(is_pwospf(packet)){
                struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
                pwospf_hdr_t *pwospf_hdr = (pwospf_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
                if(pwospf_hdr->type == PWOSPF_TYPE_HELLO){
                    struct pwospf_hello *hello = (struct pwospf_hello *)(pwospf_hdr + sizeof(pwospf_hdr_t));
                    
                    uint32_t neighbor_id = pwospf_hdr->router_id;
                    struct sr_if* this_iface = sr_get_interface(sr, interface);
                    uint32_t subnet = this_iface->ip & this_iface->mask; // Already in host byte order
                    uint32_t mask = this_iface->mask;

                    //L3 Lock
                    struct pwospf_if* interfaces = sr->ospf_subsys->router->interfaces;
                    struct link_state_entry track_lsdb;
                    int change1=0;
                    while(interfaces) {
                        if (strncmp(interfaces->iface->name,this_iface->name,strlen(this_iface->name))==0) {
                            interfaces->last_hello_time = time(NULL);
                            if(interfaces->neighbor_id != neighbor_id){
                                interfaces->neighbor_id = neighbor_id;

                                track_lsdb.source_router_id = sr->ospf_subsys->router->router_id;
                                track_lsdb.neighbor_router_id = neighbor_id;
                                track_lsdb.subnet = interfaces->iface->ip&interfaces->iface->mask;
                                track_lsdb.mask = interfaces->iface->mask;
                                strncpy(track_lsdb.interface, interfaces->iface->name, SR_IFACE_NAMELEN);

                                change1=1;
                            }
                            interfaces->neighbor_ip = ip_hdr->ip_src.s_addr;

                            break;
                        }
                        interfaces = interfaces->next;
                    }
                    //L3 Unlock

                    if(change1){
                        printf("Change1 (Link Up) detected \n");
                        //L2 Lock
                        update_lsdb(track_lsdb.source_router_id,
                            track_lsdb.neighbor_router_id,
                            track_lsdb.subnet,
                            track_lsdb.mask,
                            1,
                            track_lsdb.interface);
                        //L2 Unlock
                        //L1 Lock
                        //Routing Table Update
                        //L1 Unlock
                    }
                    // uint32_t source_router_id = sr->ospf_subsys->router->router_id;
                    // update_lsdb(source_router_id, neighbor_id, subnet, mask, 1, interface);
                    // create_routing_table(sr->ospf_subsys->router->router_id);
                    // link_static_and_dynamic_tables(sr);  
                }
                else{
                    //handle lsu
                    //L2 Lock
                    //LSDB Update
                    //L2 Unlock

                    //Check Change                    
                    //L1 Lock
                    //Routing Table Update
                    //L1 Unlock
                }
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

int is_pwospf(uint8_t *packet){
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)packet;
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
    if (ip_hdr->ip_p != OSPF_PROTOCOL_NUMBER) {
        return 0; // Not an OSPF packet
    }
    return 1;
}