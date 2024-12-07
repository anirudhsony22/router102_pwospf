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
#define PWOSPF_TYPE_LSU      4
#define OSPF_PROTOCOL_NUMBER 89
#define ALLSPFROUTERS        0xe0000005  /* 224.0.0.5 in hex */
#define PWOSPF_AU_TYPE       0
#define PWOSPF_AREA_ID       0
#define HELLO_INTERVAL       10          /* Hello interval in seconds */
#define HELLO_TIMEOUT        25
#define MAX_LINK_STATE_ENTRIES 15 /*No of rows in link state database*/
#define DEFAULT_LSU_TTL      5
#define MAX_ROUTERS 10

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
    // pwospf_hello_t;
} pwospf_hdr_t;

/* PWOSPF Hello Packet Structure */
typedef struct pwospf_hello {
    uint32_t network_mask;    /* Network mask of the interface */
    uint16_t hello_int;       /* Hello interval in seconds (default 10s) */
    uint16_t padding;         /* Padding (set to 0) */
} pwospf_hello_t;

typedef struct lsu_hdr {
    uint32_t sequence;     /* Sequence number to track updates */
    uint8_t ttl;           /* Time-to-live for the LSU */
    uint8_t padding[3];    /* Padding for alignment */
    uint32_t num_ads;      /* Number of link-state advertisements */
} lsu_hdr_t;

typedef struct lsu_adv {
    uint32_t subnet;    /* Subnet of the advertised link */
    uint32_t mask;      /* Subnet mask of the advertised link */
    uint32_t router_id; /* Router ID of the neighboring router */
} lsu_adv_t;

#pragma pack(pop)

/* PWOSPF Router Structure */
struct pwospf_router {
    uint32_t router_id;       /* 32-bit Router ID */ //Big Endian
    uint32_t area_id;         /* 32-bit Area ID */ //--
    uint16_t lsuint;          /* 16-bit LSU interval in seconds */ //--
    struct pwospf_if* interfaces; /* List of PWOSPF interfaces */ //--
    pthread_mutex_t lock;     /* Mutex for thread safety */ //--
    uint32_t sequence_number;
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

/* Link State Entry */
typedef struct link_state_entry {
    uint32_t source_router_id;
    uint32_t neighbor_router_id; // Neighbor router ID
    uint32_t subnet;             // Subnet of the link
    uint32_t mask;               // Subnet mask
    time_t last_hello_time;      // Timer for the last Hello packet
    uint8_t state;               // Link state: Valid (1) or Invalid (0)
    uint8_t color;
} link_state_entry_t;

struct link_state_entry ls_db[MAX_LINK_STATE_ENTRIES];



typedef struct sequence_table_entry {
    uint32_t source_router_id;  // Source router ID
    uint32_t last_sequence_num; // Last seen sequence number
} sequence_table_entry_t;

struct sequence_table_entry seq[MAX_ROUTERS];


int pwospf_init(struct sr_instance* sr);
void* populate_pwospf(void* sr_arg);

#endif /* SR_PWOSPF_H */
