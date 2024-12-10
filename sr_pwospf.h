/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */


    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

int pwospf_init(struct sr_instance* sr);

struct pwospf_router {
    uint32_t router_id;       //Big-endian
    uint32_t area_id;         //Big-endian
    uint16_t lsuint;          
    struct pwospf_if* interfaces; 
    pthread_mutex_t lock;     
    uint32_t sequence_number;
};

/* PWOSPF Interface Structure */
struct pwospf_if {
    struct sr_if* iface;          
    uint16_t helloint;            
    uint32_t neighbor_id;       //Big-endian
    uint32_t neighbor_ip;       //Big-endian
    time_t last_hello_time;       
    struct pwospf_if* next;       
};

struct pwospf_subsys {
    struct pwospf_router* router; 
    pthread_t thread;             
    pthread_mutex_t lock;         
};

typedef struct pwospf_hdr {
    uint8_t  version;         
    uint8_t  type;            
    uint16_t packet_length;   
    uint32_t router_id;       //Big-endian
    uint32_t area_id;         //Big-endian
    uint16_t checksum;        
    uint16_t autype;          
    uint64_t authentication;  
} pwospf_hdr_t;

typedef struct pwospf_hello {
    uint32_t network_mask;    //Big-endian
    uint16_t hello_int;       
    uint16_t padding;         
} pwospf_hello_t;

#endif /* SR_PWOSPF_H */
