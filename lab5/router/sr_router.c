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
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "vnscommand.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/


/*Longest Match*/

/*struct sr_rt* longest_match(struct sr_instance* router, uint32_t ipaddr){
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
}*/


void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
   
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
   
    /* Add initialization code here! */

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
void sr_handleIP(struct sr_instance* sr,uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */){
 

    sr_ethernet_hdr_t ether_hdr_ip;
    memcpy((uint8_t*)&ether_hdr_ip, packet, sizeof(sr_ethernet_hdr_t));
    assert(ntohs(ether_hdr_ip.ether_type) == ethertype_ip);
    sr_ip_hdr_t* ip_hd = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t* ether_hdr2 = (sr_ethernet_hdr_t*) packet;

 if(cksum(packet, sizeof(sr_ip_hdr_t)) == 0xFFFF){
   
   return;
 }

printf("Finish cheking the checksum\n");
 struct sr_if* sr_if_interface = sr_get_interface(sr, interface);
 struct sr_if* list = sr->if_list;
 int selfIP = 0;
  while(list != NULL){
   
    if(list->ip == ip_hd->ip_dst){
      printf("Own IP\n");
      selfIP = 1;
     
      if(ip_hd->ip_p == ip_protocol_icmp){
        sr_icmp_hdr_t*  icmp_hd = (sr_icmp_hdr_t*)(ip_hd +1);
       
       
        if(icmp_hd->icmp_type == 8){
          unsigned int send_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_hd->ip_len);

          /* malloc the space for the send_packet */
          uint8_t* send_packet = (uint8_t*) malloc(send_len);

          /* obtain the send etherned header */
          sr_ethernet_hdr_t *send_ethernet_hdr = (sr_ethernet_hdr_t *) send_packet;
          /* obtain the send ip header */
          sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t));
          /* obtain the send icmp header */
          sr_icmp_t8_hdr_t *send_icmp_hdr = (sr_icmp_t8_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          /* copy the entire icmp header and payload */
          memcpy(send_icmp_hdr, icmp_hd, send_len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));

          /* set the icmp code and type */
          send_icmp_hdr->icmp_code = 0;
          send_icmp_hdr->icmp_type = 0;
          /* set the checksum of icmp packet */
          send_icmp_hdr->icmp_sum = 0;
          send_icmp_hdr->icmp_sum=cksum(send_icmp_hdr, send_len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
         

          memcpy(send_ip_hdr, ip_hd, sizeof(sr_ip_hdr_t));
          /* when you set the ip_header length, you should set it like this */
          send_ip_hdr->ip_sum = 0;
          send_ip_hdr->ip_len = htons(send_len-sizeof(sr_ethernet_hdr_t));
          send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));
          send_ip_hdr->ip_src = ip_hd->ip_dst;
          send_ip_hdr->ip_dst = ip_hd->ip_src;

          memcpy(send_ethernet_hdr->ether_shost, sr_if_interface->addr, ETHER_ADDR_LEN);
          send_ethernet_hdr->ether_type = htons(ethertype_ip);

        struct sr_arpentry* arp_entry = sr_arpcache_lookup((&sr->cache), ip_hd->ip_dst);
        uint8_t* dest = arp_entry->mac;
        if(dest ==NULL){
          memset(send_ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
        else{
        memcpy(send_ethernet_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
        }

         
         
          sr_send_packet(sr, send_packet, send_len, interface);
         
          free(send_packet);
          



        }
      }

      else{
       
        unsigned int send_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

        /* malloc the space for the send_packet */
        uint8_t* send_packet = malloc(send_len);

        /* obtain the send etherned header */
        sr_ethernet_hdr_t *send_ethernet_hdr = (sr_ethernet_hdr_t *) send_packet;
        /* obtain the send ip header */
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t));
        /* obtain the send icmp header */
        sr_icmp_t3_hdr_t *send_icmp_hdr = (sr_icmp_t3_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* copy the entire icmp header and payload */
       

       

        memcpy(send_ip_hdr, ip_hd, sizeof(sr_ip_hdr_t));
        /* when you set the ip_header length, you should set it like this */
        send_ip_hdr->ip_p = ip_protocol_icmp;
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_len = htons(send_len-sizeof(sr_ethernet_hdr_t));
       
        send_ip_hdr->ip_src = ip_hd->ip_dst;
        send_ip_hdr->ip_dst = ip_hd->ip_src;
       
        send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));

        memcpy(send_ethernet_hdr->ether_shost, sr_if_interface->addr, ETHER_ADDR_LEN);
        send_ethernet_hdr->ether_type = htons(ethertype_ip);

        struct sr_arpentry* arp_entry = sr_arpcache_lookup((&sr->cache), ip_hd->ip_dst);
        uint8_t* dest = arp_entry->mac;
        if(dest ==NULL){
          memset(send_ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
        else{
        memcpy(send_ethernet_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
        }

        /* set the icmp code and type */
        send_icmp_hdr->icmp_code = 3;
        send_icmp_hdr->icmp_type = 3;
        /* set the checksum of icmp packet */
        send_icmp_hdr->icmp_sum = 0;
        memcpy(send_icmp_hdr->data , ip_hd, ICMP_DATA_SIZE);
        send_icmp_hdr->icmp_sum=cksum(send_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
       

     
        sr_send_packet(sr, send_packet, send_len, interface);
           
        free(send_packet);

      }
     
      /* do things*/

    }
    list = list->next;
  }
  if(selfIP != 0){
    return;
  }
  printf("Not own IP\n");
  if(ip_hd->ip_ttl == 1){

        unsigned int send_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);

        /* malloc the space for the send_packet */
        uint8_t* send_packet = malloc(send_len);

        /* obtain the send etherned header */
        sr_ethernet_hdr_t *send_ethernet_hdr = (sr_ethernet_hdr_t *) send_packet;
        /* obtain the send ip header */
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t));
        /* obtain the send icmp header */
        sr_icmp_t11_hdr_t *send_icmp_hdr = (sr_icmp_t11_hdr_t *) (send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        /* copy the entire icmp header and payload */
       
       
       

        memcpy(send_ip_hdr, ip_hd, sizeof(sr_ip_hdr_t));
        send_ip_hdr->ip_sum = 0;
        /* when you set the ip_header length, you should set it like this */
        send_ip_hdr->ip_len = htons(send_len-sizeof(sr_ethernet_hdr_t));
        send_ip_hdr->ip_p = ip_protocol_icmp;
        send_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
        send_ip_hdr->ip_dst = ip_hd->ip_src;
        send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));
        /*send_ip_hdr->ip_p = ip_protocol_icmp;*/

        memcpy(send_ethernet_hdr->ether_shost, sr_if_interface->addr, ETHER_ADDR_LEN);
        send_ethernet_hdr->ether_type = htons(ethertype_ip);

       struct sr_arpentry* arp_entry = sr_arpcache_lookup((&sr->cache), ip_hd->ip_dst);
        uint8_t* dest = arp_entry->mac;
        if(dest ==NULL){
          memset(send_ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
        else{
        memcpy(send_ethernet_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
        }


         /* set the icmp code and type */
        send_icmp_hdr->icmp_code = 0;
        send_icmp_hdr->icmp_type = 11;
        /* set the checksum of icmp packet */
        send_icmp_hdr->icmp_sum = 0;
        memcpy(send_icmp_hdr->data , ip_hd, ICMP_DATA_SIZE);
        send_icmp_hdr->icmp_sum=cksum(send_icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

       
        sr_send_packet(sr, send_packet, send_len, interface);
       
        free(send_packet);

   

  }
  else{
    struct sr_rt* rt_table = sr->routing_table;
    struct sr_rt* rt_match = NULL;
    uint32_t ip_destination = ip_hd->ip_dst;

    while(rt_table != NULL){
      if((rt_table->dest.s_addr & rt_table->mask.s_addr) == (ip_destination & rt_table->mask.s_addr)){
        rt_match = rt_table;
      }
      rt_table = rt_table->next;
    }

    printf("not for my own ip\n");

    if(rt_match == NULL){
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

        memcpy(send_ethernet_hdr->ether_shost, sr_if_interface->addr, ETHER_ADDR_LEN);
        send_ethernet_hdr->ether_type = htons(ethertype_ip);

       struct sr_arpentry* arp_entry = sr_arpcache_lookup((&sr->cache), ip_hd->ip_dst);
        uint8_t* dest = arp_entry->mac;
        if(dest ==NULL){
          memset(send_ethernet_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
        }
        else{
        memcpy(send_ethernet_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
        }

        send_icmp_hdr->icmp_code = 0;
        send_icmp_hdr->icmp_type = 3;
        /* set the checksum of icmp packet */
        send_icmp_hdr->icmp_sum = 0;
        memcpy(send_icmp_hdr->data , ip_hd, ICMP_DATA_SIZE);
        send_icmp_hdr->icmp_sum=cksum(send_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

       
        sr_send_packet(sr, send_packet, send_len, interface);
       
        free(send_packet);

    }
    else{
        /* obtain the send etherned header */
        sr_ethernet_hdr_t *send_ethernet_hdr = (sr_ethernet_hdr_t *) packet;
        /* obtain the send ip header */
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
       
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_ttl = send_ip_hdr->ip_ttl-1;
        /* when you set the ip_header length, you should set it like this */
        send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));

        memcpy(send_ethernet_hdr->ether_shost, sr_get_interface(sr, rt_match->interface)->addr, ETHER_ADDR_LEN);
        struct sr_arpentry* arp_entry = sr_arpcache_lookup((&sr->cache), rt_match->gw.s_addr);
      
        if(arp_entry){
          memcpy(send_ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
          sr_send_packet(sr, packet, len, rt_match->interface);
        }
        else{
          printf("Cache packet to queue\n");
          sr_arpcache_queuereq(&sr->cache, rt_match->gw.s_addr, packet, len, rt_match->interface);
        }
     
    }

  }
 
}
void sr_handleARP(struct sr_instance* sr,uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */){
       
  sr_ethernet_hdr_t ether_hdr;
  memcpy((uint8_t*)&ether_hdr, packet, sizeof(sr_ethernet_hdr_t));
  assert(ntohs(ether_hdr.ether_type) == ethertype_arp);
  sr_arp_hdr_t* arp = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t* ether_hdr2 = (sr_ethernet_hdr_t*) packet;
         
  if(arp->ar_op == htons(arp_op_request)){

          /*printf("received an arp packet\n");*/
    struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);

    if (req){
      struct sr_packet* p;
      for (p = req->packets; p!= 0; p = p->next){
        sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*)p -> buf;
        memcpy(ether_hdr->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);

        struct sr_if* outgoing_if = sr_get_interface(sr, p->iface);
        assert(outgoing_if);
        memcpy(ether_hdr->ether_shost, outgoing_if->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, p->buf, p->len, p->iface);
      }
      sr_arpreq_destroy(&sr->cache, req);
    }

    uint8_t* outgoing_packet = malloc (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t* ether_hdr_resp = (sr_ethernet_hdr_t* ) outgoing_packet;
     
    sr_arp_hdr_t* arp_resp = (sr_arp_hdr_t*) (outgoing_packet+sizeof(sr_ethernet_hdr_t));

    struct sr_if* sr_if_resp = sr_get_interface(sr, interface);
         
    arp_resp->ar_hrd = htons(arp_hrd_ethernet);
    arp_resp->ar_pro = htons(ethertype_ip);
    arp_resp->ar_hln = ETHER_ADDR_LEN;
    arp_resp->ar_pln = 4;
    arp_resp->ar_op = htons(arp_op_reply);
         
    arp_resp->ar_sip = sr_if_resp->ip;
    memcpy(arp_resp->ar_sha, sr_if_resp->addr, sizeof(sr_if_resp->addr));
         
    arp_resp->ar_tip = arp->ar_sip;
    memcpy(arp_resp->ar_tha, arp->ar_sha, sizeof(arp->ar_sha));  
         
         
    memcpy(ether_hdr_resp->ether_dhost, arp->ar_sha, sizeof(arp->ar_sha));
    memcpy(ether_hdr_resp->ether_shost, sr_if_resp->addr, sizeof(ether_hdr2->ether_dhost));
         
    ether_hdr_resp->ether_type = htons(ethertype_arp);
         
         
          /*print_hdr_arp(arp);
          print_hdr_arp(arp_resp);
          print_hdr_eth(outgoing_packet);
          */
    sr_send_packet(sr, outgoing_packet, len, interface); 
    free(outgoing_packet);   
  }
  else if((arp->ar_op == htons(arp_op_reply))){
    struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);

    if (req){
      struct sr_packet* p;
      for (p = req->packets; p!= 0; p = p->next){
        sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*)p -> buf;
        memcpy(ether_hdr->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
        sr_send_packet(sr, p->buf, p->len, p->iface);
      }

      sr_arpreq_destroy(&sr->cache, req);
    }
  }
}
       


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /*printf("*** -> Received packet of length %d \n",len);*/

  if(len < sizeof(struct sr_ethernet_hdr_t*)){
    /*fprintf(stderr, "packet len is less than minimum ethernet heade\n");*/
  }
  assert(len >= sizeof(struct sr_ethernet_hdr));

  sr_ethernet_hdr_t ether_hdr;
  memcpy((uint8_t*)&ether_hdr, packet, sizeof(sr_ethernet_hdr_t));
  uint16_t pkt_type = ntohs(ether_hdr.ether_type);
  /*printf("packet type is %x\n", pkt_type);*/
 

  switch (pkt_type){
    case ethertype_ip:
     
      sr_handleIP(sr, packet, len, interface);
      break;

    case ethertype_arp:
      sr_handleARP(sr, packet, len, interface);
      break;

    default:
      /*fprintf(stderr, "error: unknown protocol ox%x\n", pkt_type);*/
      exit(1);

  }

 



  /* Lab4: Fill your code here */

}/* end sr_ForwardPacket */