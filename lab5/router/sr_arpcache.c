#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"

/*Longest Match
struct sr_rt* longest_match(struct sr_instance* router, uint32_t ipaddr){
  struct in_addr addr;
  addr.s_addr = ipaddr;
  struct sr_rt* match=NULL;
  struct sr_rt* entry;
  int maxlen = 0;
  for (entry = router->routing_table; entry != NULL; entry = entry->next) {
    if (((entry->dest.s_addr & entry->mask.s_addr) == (addr.s_addr & entry->mask.s_addr)) && (maxlen <= entry->mask.s_addr)) {
      match = entry;
      maxlen = entry->mask.s_addr;
    }
  }
  return match;
}
*/

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq* cachereqs = sr->cache.requests;
    
    struct sr_arpreq* pointer = cachereqs;
    
    printf("Start ARP CACHE SWEEPREQ\n");
    while(pointer != NULL){
        int skip = 0;
         printf("go through each pointer\n");
        if(difftime(time(NULL), pointer->sent)>1.0){
            if(pointer->times_sent < 5){
                printf("Start Send ARP REQUEST\n");
                pointer->times_sent += 1;

                uint8_t* outgoing_packet = (uint8_t* ) malloc (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
                sr_ethernet_hdr_t* ether_hdr_resp = (sr_ethernet_hdr_t* ) outgoing_packet;
                
                sr_arp_hdr_t* arp_resp = (sr_arp_hdr_t*) (outgoing_packet+sizeof(sr_ethernet_hdr_t));

        
                    
                arp_resp->ar_hrd = htons(1);
                arp_resp->ar_pro = htons(0x800);
                arp_resp->ar_hln = ETHER_ADDR_LEN;
                arp_resp->ar_pln = 4;
                arp_resp->ar_op = htons(arp_op_request);
               struct sr_rt * rt_table  = sr->routing_table;
               struct sr_rt * rt_table_match;
              
                uint32_t ip_destination = pointer->ip;

                while(rt_table != NULL){
                if((rt_table->dest.s_addr & rt_table->mask.s_addr) == (ip_destination & rt_table->mask.s_addr)){
                    rt_table_match = rt_table;
                    }
                rt_table = rt_table->next;
                }
                /*longest_match()*/
                /* Change to longest prefix, currently only does exact match*/
               /* struct sr_rt* rt_table_match = longest_match(sr, ip_destination);*/

                
                arp_resp->ar_sip = sr_get_interface(sr, rt_table_match->interface)->ip;
                memcpy(arp_resp->ar_sha, sr_get_interface(sr, rt_table_match->interface)->addr, 6);
                    
                arp_resp->ar_tip = pointer->ip;
                memset(arp_resp->ar_tha, 255, 6);  
                    
                    
                memset(ether_hdr_resp->ether_dhost, 255, 6);
                memcpy(ether_hdr_resp->ether_shost, sr_get_interface(sr, rt_table_match->interface)->addr, 6);
                    
                ether_hdr_resp->ether_type = htons(ethertype_arp);

                sr_send_packet(sr, outgoing_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), rt_table_match->interface);    
                
                pointer->sent = time(NULL);
                free(outgoing_packet);
            }
            else{
                
                sendDestHostUnrchble(sr, pointer);
                struct sr_arpreq* temp = pointer->next;
                
                sr_arpreq_destroy(&sr->cache, pointer);
                pointer = temp;
                
                skip = 1;
            }
        }
        if(skip == 0){
            pointer = pointer->next;
        } 
    }
}




void sendDestHostUnrchble(struct sr_instance *sr, struct sr_arpreq *pointer){
    struct sr_packet* packetList = pointer->packets;
    while(packetList != NULL){
        uint8_t packet = packetList->buf;
       /* char* interface = packetList->iface;*/
        
        unsigned int len = packetList->len;
        sr_ethernet_hdr_t ether_hdr_ip;
        memcpy((uint8_t*)&ether_hdr_ip, packet, sizeof(sr_ethernet_hdr_t));
        
        sr_ip_hdr_t* ip_hd = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
       /* struct sr_rt* rt_table_match = longest_match(sr, ip_hd->ip_dst);*/
         struct sr_rt * rt_table  = sr->routing_table;
               struct sr_rt * rt_table_match;
              
                uint32_t ip_destination = ip_hd->ip_dst;

                while(rt_table != NULL){
                if((rt_table->dest.s_addr & rt_table->mask.s_addr) == (ip_destination & rt_table->mask.s_addr)){
                    rt_table_match = rt_table;
                    }
                rt_table = rt_table->next;
                }

 /*while(rt_table != NULL){
                if((rt_table->dest.s_addr & rt_table->mask.s_addr) == (ip_destination & rt_table->mask.s_addr)){
                    rt_table_match = rt_table;
                    }
                rt_table = rt_table->next;
                }
    */
  


        char*interface = rt_table_match->interface;
        sr_ethernet_hdr_t* ether_hdr2 = (sr_ethernet_hdr_t*) packet;
        unsigned int send_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t); 

        /* malloc the space for the send_packet */
        uint8_t* send_packet = malloc(send_len);

        /* obtain the send etherned header */
        sr_ethernet_hdr_t *send_ethernet_hdr = (sr_ethernet_hdr_t *) send_packet;
        /* obtain the send ip header */
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t));
        /* obtain the send icmp header */
        sr_icmp_t11_hdr_t *send_icmp_hdr = (sr_icmp_t11_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* copy the entire icmp header and payload */
        

        /* set the icmp code and type */
        
        

        memcpy(send_ip_hdr, ip_hd, sizeof(sr_ip_hdr_t));
        /* when you set the ip_header length, you should set it like this */
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_len = htons(send_len-sizeof(sr_ethernet_hdr_t));
        send_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
        send_ip_hdr->ip_dst = ip_hd->ip_src;
        send_ip_hdr->ip_p = ip_protocol_icmp;
        send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));

        struct sr_if* sr_if_interface = sr_get_interface(sr, interface);
        memcpy(send_ethernet_hdr->ether_shost, sr_if_interface->addr, ETHER_ADDR_LEN);
        send_ethernet_hdr->ether_type = htons(ethertype_ip);

        struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hd->ip_src);
        memcpy(send_ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

        send_icmp_hdr->icmp_code = 1;
        send_icmp_hdr->icmp_type = 3;
        /* set the checksum of icmp packet */
        send_icmp_hdr->icmp_sum = 0;
        memcpy(send_icmp_hdr->data , ip_hd, ICMP_DATA_SIZE);
        send_icmp_hdr->icmp_sum=cksum(send_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

       
        sr_send_packet(sr, send_packet, len, interface);
        
        free(send_packet);
        free(arp_entry);
        packetList = packetList->next;
        }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = NULL;
        if (req->packets == NULL){
            req->packets = new_pkt;
        }
        else{
            struct sr_packet *p = req->packets;
            while(p->next != NULL)
                p = p->next;
            p->next = new_pkt;
        }
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

