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
    

    /* -- handle subsystem initialization here! -- */
    sr->ospf_subsys->router = malloc(sizeof(struct pwospf_router));
    pthread_mutex_init(&sr->ospf_subsys->router->lock, NULL);
    sr->ospf_subsys->router->area_id = PWOSPF_AREA_ID;
    sr->ospf_subsys->router->lsuint = 30; /* Default 30 seconds */
    sr->ospf_subsys->router->interfaces = NULL;
    sr->ospf_subsys->router->sequence_number = 0;
    sr->ospf_subsys->router->router_id = sr->if_list->ip;
    // printf("%s", get_ipstr(sr->if_list->ip));

    struct sr_if* iface = sr->if_list;
    struct pwospf_if* prev_pw_iface = NULL;
    // printf("Setting up ifs\n");
    while (iface) {
        /* Allocate memory for PWOSPF interface */
        struct pwospf_if* pw_iface = malloc(sizeof(struct pwospf_if));

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
    }
    prev_pw_iface = sr->ospf_subsys->router->interfaces;
    while(prev_pw_iface){
        printf("\n%s\n", get_ipstr(prev_pw_iface->iface->ip));
        prev_pw_iface=prev_pw_iface->next;
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

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_lock(sr->ospf_subsys);
        printf(" pwospf subsystem sleeping \n");
        pwospf_unlock(sr->ospf_subsys);
        sleep(2);
        printf(" pwospf subsystem awake \n");
    };
    return NULL;
} /* -- run_ospf_thread -- */

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
