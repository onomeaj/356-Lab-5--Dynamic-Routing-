/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance *sr, const char *filename)
{
    FILE *fp;
    char line[BUFSIZ];
    char dest[32];
    char gw[32];
    char mask[32];
    char iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if (access(filename, R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename, "r");

    while (fgets(line, BUFSIZ, fp) != 0)
    {
        sscanf(line, "%s %s %s %s", dest, gw, mask, iface);
        if (inet_aton(dest, &dest_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1;
        }
        if (inet_aton(gw, &gw_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1;
        }
        if (inet_aton(mask, &mask_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1;
        }
        if (clear_routing_table == 0)
        {
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance *sr)
{
    struct sr_if *interface = sr->if_list;
    char iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface)
    {
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance *sr, struct in_addr dest,
                     struct in_addr gw, struct in_addr mask, uint32_t metric, char *if_name)
{
    struct sr_rt *rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_locker));
    /* -- empty list special case -- */
    if (sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt *)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface, if_name, sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_locker));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while (rt_walker->next)
    {
        rt_walker = rt_walker->next;
    }

    rt_walker->next = (struct sr_rt *)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface, if_name, sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;

    pthread_mutex_unlock(&(sr->rt_locker));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance *sr)
{
    pthread_mutex_lock(&(sr->rt_locker));
    struct sr_rt *rt_walker = 0;

    if (sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_locker));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;

    while (rt_walker)
    {
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_locker));

} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt *entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    char buff[20];
    struct tm *timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t", inet_ntoa(entry->dest));
    printf("%s\t", inet_ntoa(entry->gw));
    printf("%s\t", inet_ntoa(entry->mask));
    printf("%s\t", entry->interface);
    printf("%d\t", entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */

void *sr_rip_timeout(void *sr_ptr)
{
    struct sr_instance *sr = sr_ptr;
    while (1)
    {
        sleep(5);
        sr_print_routing_table(sr);
        pthread_mutex_lock(&(sr->rt_locker));
        /* Lab5: Fill your code here */
        struct sr_rt *entry = sr->routing_table;

        /*TODO, dont forget!!!!!: Later when you want to add this entry back, you can change the metric, gw, 
        iface directly instead of adding a new entry in your routing table. However, if you implement your 
        code in this way, when you look up your routing table to forward a packet, you should ignore
         all the entries with metric value == INFINITY.)*/

        while (entry != NULL)
        {
            if (difftime(time(NULL), entry->updated_time) >= 20)
            {
                entry->metric = INFINITY; /*CONFIRM WE HAVE TO HTONL, will this remain infinity during comparison*/
            }
            entry = entry->next;
        }

        struct sr_if *if_walker = sr->if_list;
        while (if_walker)
        {
            if (sr_obtain_interface_status(sr, if_walker->name) == 0)
            {
                /*delete all the routing entries which use this interface to send packets*/ /* is it any entry whose name == if_walker-> name, delete?
                check the entry next hop if it matchthe interface and then deete?*/
                /*struct sr_rt *entry_walker = sr->routing_table;
                while(entry_walker != NULL)
                {
                    if(entry_walker->interface == if_walker->name)
                    {
                        entry_walker->metric = INFINITY;
                    }
                    entry_walker = entry_walker->next;
                }
                */

                entry = sr->routing_table;
                while(entry != NULL)
                {
                    if(entry->interface == if_walker->name)
                    {
                        entry->metric = INFINITY;
                    }
                    entry = entry->next;
                }
            }

           /* else if (sr_obtain_interface_status(sr, if_walker->name) == 1)
            {*/
                /*make sure to confirm , all speculative atm*/

                /*you should check whether your current routing table contains the subnet this interface 
                is directly connected to.
                If it contains, update the updated time. Otherwise, add this subnet to your routing table*/
            /*    struct sr_rt *entry = sr->routing_table;

                int subnetInRouting = 0;
                while (entry != NULL)
                {
                    if (((entry->dest.s_addr & entry->mask.s_addr) == (if_walker->ip & if_walker->mask)) && (entry->mask.s_addr == if_walker->mask))
                    {
                        entry->updated_time = time(NULL);
                        subnetInRouting = 1;
                    }
                    entry = entry->next;
                }
                if(!subnetInRouting)
                {
                    struct in_addr dest;
                    dest.s_addr = if_walker->ip;
                    struct in_addr mask;
                    mask.s_addr = if_walker->mask;
                    struct in_addr gw;
                    gw.s_addr = 0;
                    sr_add_rt_entry(sr, dest, gw, mask, 0, if_walker->name);
                }
            }
            */
           else{
               struct in_addr dest;
                dest.s_addr = if_walker->ip & if_walker->mask;

                /** Set metric to 0 **/
                entry = sr->routing_table;
                while(entry != NULL) {
                    if (entry->dest.s_addr == dest.s_addr) {
                        entry->metric = 0;
                        entry->updated_time = time(NULL);
                        entry->gw.s_addr = 0;
                        strncpy(entry->interface, if_walker->name, sr_IFACE_NAMELEN);
                    }
                    entry = entry->next;
                }
                
            }
			
			if_walker = if_walker->next;

           }
        
        
        send_rip_response(sr);
        pthread_mutex_unlock(&(sr->rt_locker));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr)
{
    pthread_mutex_lock(&(sr->rt_locker));
    struct sr_if *if_walker = sr->if_list;
    /* malloc space for packet*/
    while (if_walker != NULL)
    {
        unsigned int send_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
        uint8_t *outgoing_packet = (uint8_t *)malloc(send_len);
        memset(outgoing_packet, 0, send_len);

        /*create ethernet header space*/
        sr_ethernet_hdr_t *eth_hd = (sr_ethernet_hdr_t *)outgoing_packet;
        memset(eth_hd->ether_dhost, 0xff, 6); /*figure out format*/

        memcpy(eth_hd->ether_shost, if_walker->addr, 6);

        eth_hd->ether_type = htons(ethertype_ip);

        /*create ip header space*/
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(outgoing_packet + sizeof(sr_ethernet_hdr_t));
        send_ip_hdr->ip_dst = htonl(0xffffffff);
        send_ip_hdr->ip_src = if_walker->ip;
        send_ip_hdr->ip_v = 4;
        send_ip_hdr->ip_hl = 5;
        send_ip_hdr->ip_p = ip_protocol_udp;
        send_ip_hdr->ip_ttl = 16; /*16 or 64*/
        send_ip_hdr->ip_len = htons(send_len - sizeof(sr_ethernet_hdr_t));
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));

        /*fill in rest ofip and other headers using definition*/

        /*create udp header*/
        sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(outgoing_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->port_dst = htons(520);
        udp_hdr->port_src = htons(520);
        udp_hdr->udp_len = htons(sizeof(sr_rip_pkt_t) + sizeof(sr_udp_hdr_t));

        /*create rip header*/
        sr_rip_pkt_t *rip_hdr = (sr_rip_pkt_t *)(outgoing_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        rip_hdr->command = 1;
        rip_hdr->version = 2;
        rip_hdr->entries[0].metric = htonl(INFINITY);


        struct sr_rt* rt1 = sr->routing_table;
        int counter = 0;

        while (rt1 != NULL) {
            rip_hdr->entries[counter].address = rt1->dest.s_addr;
            rip_hdr->entries[counter].mask = rt1->mask.s_addr;
            rip_hdr->entries[counter].next_hop = rt1->gw.s_addr;
            rip_hdr->entries[counter].metric = htonl(0);
            rip_hdr->entries[counter].afi = htons(2);
            rip_hdr->entries[counter].tag = htons(0);
            counter += 1;
            rt1 = rt1->next;
        }

        sr_send_packet(sr, outgoing_packet, send_len, if_walker->name);
        free(outgoing_packet);

        /* Lab5: Fill your code here */
        /*rip request packet, command value different=1
        how to send to all interfaces?
        other values
        how to cast ip.dst and eth dst?
        does the packet have anydata or just all the headers?
        no data
        for loop for interface sending
        */
        if_walker = if_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_locker));
}

void send_rip_response(struct sr_instance *sr)
{
    printf("rip response pre-lock\n");
    pthread_mutex_lock(&(sr->rt_locker));
    printf("rip response lock acquired\n");
    struct sr_if *if_walker = sr->if_list;
    /* malloc space for packet*/
    while (if_walker != NULL)
    {
        unsigned int send_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
        uint8_t *outgoing_packet = (uint8_t *)malloc(send_len);
        memset(outgoing_packet, 0, send_len);

        /*create ethernet header space*/
        sr_ethernet_hdr_t *eth_hd = (sr_ethernet_hdr_t *)outgoing_packet;
        memset(eth_hd->ether_dhost, 0xff, 6); /*figure out format*/

        memcpy(eth_hd->ether_shost, if_walker->addr, 6);

        eth_hd->ether_type = htons(ethertype_ip);

        /*create ip header space*/
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(outgoing_packet + sizeof(sr_ethernet_hdr_t));
        send_ip_hdr->ip_dst = 0xffffffff;
        send_ip_hdr->ip_src = if_walker->ip;
        send_ip_hdr->ip_v = 4;
        send_ip_hdr->ip_hl = 5;
        send_ip_hdr->ip_p = ip_protocol_udp;
        send_ip_hdr->ip_ttl = 64;
        send_ip_hdr->ip_len = htons(send_len - sizeof(sr_ethernet_hdr_t));
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));

        /*fill in rest ofip and other headers using definition*/

        /*create udp header*/
        sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(outgoing_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        udp_hdr->port_dst = htons(520);
        udp_hdr->port_src = htons(520);
        udp_hdr->udp_len = htons(sizeof(sr_rip_pkt_t) + sizeof(sr_udp_hdr_t));

        /*create rip header*/
        sr_rip_pkt_t *rip_hdr = (sr_rip_pkt_t *)(outgoing_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        rip_hdr->command = 2;
        rip_hdr->version = 2;

        struct sr_rt *entry = sr->routing_table;
        int index = 0;
        while (entry != NULL)
        {
            if (strcmp(entry->interface, if_walker->name) != 0 || (time(NULL) - entry->updated_time >= 20))
            {
                rip_hdr->entries[index].afi = htons(2);
                rip_hdr->entries[index].address = entry->dest.s_addr;
                rip_hdr->entries[index].mask = entry->mask.s_addr;
                rip_hdr->entries[index].metric = htonl(entry->metric);
                rip_hdr->entries[index].next_hop = entry->gw.s_addr;
                entry = entry->next;
                index++;
            }
        }
        
        sr_send_packet(sr, outgoing_packet, send_len, if_walker->name);
        printf("rip response sent\n");
        free(outgoing_packet);

        
        if_walker = if_walker->next;
        
    }
    pthread_mutex_unlock(&(sr->rt_locker));
    printf("rip response lock released\n");

    
}

uint32_t min(uint32_t a, uint32_t b)
{
    if(a < b)
    {
        return a;
    }
    else
    {
        return b;
    }
}
struct sr_rt *longest_match(struct sr_instance *router, uint32_t ipaddr);

void update_route_table(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    printf("updating routing pre-lock\n");
    pthread_mutex_lock(&(sr->rt_locker));
    printf("updating routing lock acquired\n");
    sr_ethernet_hdr_t *eth_hd = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t *ip_hd = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_udp_hdr_t *udp_hd = (sr_udp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    sr_rip_pkt_t *rip_packet = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
    
    int i;
    struct sr_if* if_walker = sr_get_interface(sr, interface);

    for(i = 0; i < MAX_NUM_ENTRIES; i++)
    {

       
        struct entry currentEntry = rip_packet->entries[i];

        if((if_walker->ip) == (currentEntry.next_hop)){
            continue;
        }
        printf("looping through entries, current entry: %d\n", i);
        int updatedRT = 0;
        if(currentEntry.afi == 0)
        {
            printf("afi is 0\n");
            break;
        }
        
        uint32_t currentMetric = min(currentEntry.metric+1, INFINITY);
        struct sr_rt* rt_entry = sr->routing_table;

        while(rt_entry != NULL)
        {
            
            if ((currentEntry.address & currentEntry.mask) == (rt_entry->dest.s_addr & rt_entry->mask.s_addr)) /*contains the entry*/
            {
                printf("contains entry\n");
                struct in_addr ipAdd;
                ipAdd.s_addr = ip_hd->ip_src;
                
                
                /*if packet is from same router as the entry -- CHECK THAT THIS IS RIGHT*/
                /*if(rt_entry->gw.s_addr == ip_hd->ip_src)*/
                if(rt_entry->gw.s_addr == ipAdd.s_addr)

                {
                    /*update updated time and metric*/
                    /*says to delete if metric is infinity, but we can just set it as infinity and change it later when we get new response*/
                    rt_entry->updated_time = time(NULL);
                    rt_entry->metric = currentMetric;
                    printf("from same router\n");
                }
                else
                {

                    /*else: 
                    Otherwise, compare the metric and the current metric in this entry. 
                    If metric < current metric in routing table, 
                    updating all the information in the routing entry*/

                    if(currentMetric < rt_entry->metric)
                    {
                        rt_entry->gw.s_addr = ipAdd.s_addr;/*CHANGED FROM IP_HD*/
                        rt_entry->mask.s_addr = currentEntry.mask;
                        strcpy(rt_entry->interface, interface);
                        updatedRT = 1;
                        printf("not from same router, updating metric, mask, intf\n");
                    }

                
                }
            }
            else
            {
                printf("does not contain entry\n");
                struct in_addr dest;
                dest.s_addr = currentEntry.address;
                struct in_addr mask;
                mask.s_addr = currentEntry.mask;
                struct in_addr gw;
                gw.s_addr = ip_hd->ip_src;
                
                printf("adding entry\n");
                sr_add_rt_entry(sr, dest, gw, mask, currentMetric, interface);
                printf("entry added\n");
               
                printf("re-acquired lock\n");
                updatedRT = 1;
            }
            if(updatedRT)
            {
                printf("updated routing table\n");
               
                printf("sending rip response\n");
                send_rip_response(sr);
                
                printf("rip response sent\n");
            }
            rt_entry = rt_entry->next;
        }

    }

    pthread_mutex_unlock(&(sr->rt_locker));
}


