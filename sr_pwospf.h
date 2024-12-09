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

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/time.h>
#include "sr_if.h"

#define PWOSPF_VERSION       2
#define PWOSPF_TYPE_HELLO    1
#define PWOSPF_TYPE_LSU      4
#define OSPF_PROTOCOL_NUMBER 89
#define ALLSPFROUTERS        0xe0000005
#define PWOSPF_AU_TYPE       0
#define PWOSPF_AREA_ID       0
#define HELLO_INTERVAL       10
#define HELLO_TIMEOUT        25
#define MAX_LINK_STATE_ENTRIES 15 
#define DEFAULT_LSU_TTL      5
#define MAX_ROUTERS 10
#define WHITE 0 
#define GRAY 1  
#define BLACK 2 

#pragma pack(push, 1)

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

typedef struct lsu_hdr {
    uint32_t sequence;     
    uint8_t ttl;           
    uint8_t padding[3];    
    uint32_t num_ads;      
} lsu_hdr_t;

typedef struct lsu_adv {
    uint32_t subnet;    //Big-endian
    uint32_t mask;      //Big-endian
    uint32_t router_id; //Big-endian
} lsu_adv_t;

#pragma pack(pop)


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

struct sr_instance;

struct pwospf_subsys {
    struct pwospf_router* router; 
    pthread_t thread;             
    pthread_mutex_t lock;         
};

/* Link State Entry */
typedef struct link_state_entry {
    uint32_t source_router_id; //Big-endian
    uint32_t neighbor_router_id; //Big-endian
    uint32_t subnet;             //Big-endian
    uint32_t mask;               //Big-endian
    char interface[SR_IFACE_NAMELEN];
    time_t last_hello_time;      
    uint8_t state;               
    uint8_t color;
} link_state_entry_t;
struct link_state_entry ls_db[MAX_LINK_STATE_ENTRIES];


typedef struct sequence_table_entry {
    uint32_t source_router_id;  //Big-endian
    uint32_t last_sequence_num; 
} sequence_table_entry_t;
struct sequence_table_entry seq[MAX_ROUTERS];

typedef struct queue {
    uint32_t neighbor_router_id;
    uint32_t subnet;
    uint32_t mask;
    uint8_t color;
    char interface[SR_IFACE_NAMELEN];
    uint32_t next_hop; // Extension to include next hop information
} queue_entry_t;







int pwospf_init(struct sr_instance* sr);
void* populate_pwospf(void* sr_arg);

#endif /* SR_PWOSPF_H */
