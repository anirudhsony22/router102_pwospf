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

/* Constants Definitions */
#define PWOSPF_VERSION       2
#define PWOSPF_TYPE_HELLO    1
#define OSPF_PROTOCOL_NUMBER 89
#define ALLSPFROUTERS        0xe0000005  /* 224.0.0.5 in hex */
#define PWOSPF_AU_TYPE       0
#define PWOSPF_AREA_ID       0
#define HELLO_INTERVAL       10          /* Hello interval in seconds */

/* Ensure structures are packed without padding */
#pragma pack(push, 1)

/* PWOSPF Header Structure */
typedef struct pwospf_hdr {
    uint8_t  version;         /* Version number (2 for PWOSPF/OSPFv2) */
    uint8_t  type;            /* Packet type (1 for Hello) */
    uint16_t packet_length;   /* Total packet length in bytes */
    uint32_t router_id;       /* Router ID (source) */
    uint32_t area_id;         /* Area ID (set to 0) */
    uint16_t checksum;        /* Packet checksum */
    uint16_t autype;          /* Authentication type (0 for PWOSPF) */
    uint64_t authentication;  /* Authentication data (set to 0) */
} pwospf_hdr_t;

/* PWOSPF Hello Packet Structure */
typedef struct pwospf_hello {
    uint32_t network_mask;    /* Network mask of the interface */
    uint16_t hello_int;       /* Hello interval in seconds (default 10s) */
    uint16_t padding;         /* Padding (set to 0) */
} pwospf_hello_t;

#pragma pack(pop)

/* PWOSPF Router Structure */
struct pwospf_router {
    uint32_t router_id;       /* 32-bit Router ID */ //Big Endian
    uint32_t area_id;         /* 32-bit Area ID */ //--
    uint16_t lsuint;          /* 16-bit LSU interval in seconds */ //--
    struct pwospf_if* interfaces; /* List of PWOSPF interfaces */ //--
    pthread_mutex_t lock;     /* Mutex for thread safety */ //--
};

/* PWOSPF Interface Structure */
struct pwospf_if {
    struct sr_if* iface;          /* Pointer to the associated sr_if */  //
    uint16_t helloint;            /* 16-bit Hello interval in seconds */ //
    uint32_t neighbor_id;         /* 32-bit Neighbor Router ID */ //Big Endian
    uint32_t neighbor_ip;         /* 32-bit Neighbor IP address */ //Big Endian
    time_t last_hello_time;       /* Timestamp of the last received Hello */
    struct pwospf_if* next;       /* Pointer to the next PWOSPF interface */
};

/* forward declare */
struct sr_instance;

/* PWOSPF Subsystem Structure */
struct pwospf_subsys {
    struct pwospf_router* router; /* Pointer to the PWOSPF router */
    pthread_t thread;             /* PWOSPF thread */
    pthread_mutex_t lock;         /* Mutex for thread safety */
};


int pwospf_init(struct sr_instance* sr);
void* populate_pwospf(void* sr_arg);

#endif /* SR_PWOSPF_H */
