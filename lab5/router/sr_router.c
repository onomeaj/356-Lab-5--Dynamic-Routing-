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

void sr_init(struct sr_instance *sr)
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



void handleICMP(struct sr_instance *sr, char *interface, uint8_t *packet, int type, int code)
/*IMPORTANT TYPE/CODE COMBINATIONS:
Echo reply: type 0 (code 0)
Destination Net Unreachable: type 3, code 0
Destination Host Unreachable: type 3, code 1
Destination Port Unreachable: type 3, code 3
Time exceeded: type 11, code 0*/
{
  sr_ip_hdr_t *ip_hd = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *sr_if_interface = sr_get_interface(sr, interface);
  unsigned int send_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_hd->ip_len);
  uint8_t *send_packet = (uint8_t *)malloc(send_len);
  


  /*CREATE IP HEADER*/
  sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t));
  memcpy(send_ip_hdr, ip_hd, sizeof(sr_ip_hdr_t));
  send_ip_hdr->ip_p = ip_protocol_icmp;
  send_ip_hdr->ip_len = htons(send_len - sizeof(sr_ethernet_hdr_t));
  send_ip_hdr->ip_dst = ip_hd->ip_src;
  

  if(type == 0)
  {
    printf("Creating echo response\n");
    send_ip_hdr->ip_src = ip_hd->ip_dst;
  }
  else
  {
    send_ip_hdr->ip_src = sr_if_interface->ip;
  }
  send_ip_hdr->ip_sum = 0;
  send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));
  
  


  /*CREATE ICMP HEADER*/
  if (type == 0)
  {
    sr_icmp_t8_hdr_t *send_icmp_hdr = (sr_icmp_t8_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_icmp_hdr_t *icmp_hd = (sr_icmp_hdr_t *)(ip_hd + 1);
    memcpy(send_icmp_hdr, icmp_hd, send_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    send_icmp_hdr->icmp_code = code;
    send_icmp_hdr->icmp_type = type;
    send_icmp_hdr->icmp_sum = 0;
    send_icmp_hdr->icmp_sum = cksum(send_icmp_hdr, send_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else if (type == 11)
  {
    sr_icmp_t11_hdr_t *send_icmp_hdr = (sr_icmp_t11_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    memcpy(send_icmp_hdr->data, ip_hd, ICMP_DATA_SIZE);
    send_icmp_hdr->icmp_code = code;
    send_icmp_hdr->icmp_type = type;
    send_icmp_hdr->icmp_sum = 0;
    send_icmp_hdr->icmp_sum = cksum(send_icmp_hdr, send_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else if (type == 3)
  {
    sr_icmp_t3_hdr_t *send_icmp_hdr = (sr_icmp_t3_hdr_t *)(send_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    memcpy(send_icmp_hdr->data, ip_hd, ICMP_DATA_SIZE);
    send_icmp_hdr->icmp_code = code;
    send_icmp_hdr->icmp_type = type;
    send_icmp_hdr->icmp_sum = 0;
    send_icmp_hdr->icmp_sum = cksum(send_icmp_hdr, send_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }


  /*CREATE ETHERNET HEADER*/
  sr_ethernet_hdr_t *send_ethernet_hdr = (sr_ethernet_hdr_t *)send_packet;
  memcpy(send_ethernet_hdr->ether_shost, sr_if_interface->addr, ETHER_ADDR_LEN);
  send_ethernet_hdr->ether_type = htons(ethertype_ip);

  struct sr_arpentry *arp_entry = sr_arpcache_lookup((&sr->cache), send_ip_hdr->ip_dst);
  uint8_t *dest = arp_entry->mac;
  if (dest == NULL)
  {
    printf("Destination MAC not in ARP cache\n");
    sr_arpcache_queuereq(&sr->cache, send_ip_hdr->ip_dst, send_packet, send_len, interface);
  }
  else
  {
    /*Complete Ethernet header and send packet; free malloc'd space*/
    memcpy(send_ethernet_hdr->ether_dhost, dest, ETHER_ADDR_LEN);
    sr_send_packet(sr, send_packet, send_len, interface);
    printf("ICMP packet sent\n");
    free(send_packet);
  }
}

struct sr_rt *longest_match(struct sr_instance *router, uint32_t ipaddr)
{
  printf("longest match search\n");
  struct in_addr addr;
  addr.s_addr = ipaddr;
  printf("destination IP: %d\n", ipaddr);
  struct sr_rt *match = NULL;
  struct sr_rt *entry;
  int maxlen = 0;
  for (entry = router->routing_table; entry != NULL; entry = entry->next)
  {
    if (((entry->dest.s_addr & entry->mask.s_addr) == (addr.s_addr & entry->mask.s_addr)) && (maxlen <= entry->mask.s_addr))
    {
      match = entry;
      maxlen = entry->mask.s_addr;
    }
  }
  return match;
}

void sr_handleIP(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{
  sr_ethernet_hdr_t* ether_hdr_ip = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t *ip_hd = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  print_addr_ip_int(ntohl(ip_hd->ip_dst));

  
  uint16_t recv = ip_hd->ip_sum;
  ip_hd->ip_sum = 0;
  uint16_t sum = cksum(ip_hd, sizeof(sr_ip_hdr_t));
  if ((sum) != recv)
  {
    printf("checksum is bad\n");
    printf("checksum: %d\n received: %d", sum, recv);
    return;
  }
  printf("Finished checking the checksum\n");

  struct sr_if *list = sr->if_list;
  int selfIP = 0;

  /*format of broadcast IP??*/
  /*broadcast thing fixed */
  uint32_t broadcast_ip = 0xffffffff;
  if((ip_hd->ip_dst) == (broadcast_ip))
  {
    /*ip is broadcast ip*/
    if(ip_hd->ip_p == ip_protocol_udp)
    {
      /*handled cast*/
      sr_udp_hdr_t* udp_header = (sr_udp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
      if((udp_header->port_src == ntohs(520)) && (udp_header->port_dst == ntohs(520)))
      {
        /*handled cast*/
        sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t*) (packet + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        if(rip_hdr->command == 1) /*if rip request*/
        {
          send_rip_response(sr);
        }
        else
        {
          update_route_table(sr, packet, len, interface);
        }
      }
      else
      {
        handleICMP(sr, interface, packet, 3,  3);
      }
    }
  }
  else
  /*old protocol*/
  {

    while (list != NULL)
    {
      /* If IP in router's own interface*/
      if (list->ip == ip_hd->ip_dst)
      {
        printf("Own IP\n");
        selfIP = 1;
        /*if interface up: keep old logic?*/
        if(sr_obtain_interface_status(sr, interface))
        {
          if (ip_hd->ip_p == ip_protocol_icmp)
          {
            sr_icmp_hdr_t *icmp_hd = (sr_icmp_hdr_t *)(ip_hd + 1);
            /*If packet is an echo request*/
            if (icmp_hd->icmp_type == 8)
            {
              printf("Echo request\n");
              /*Send ICMP echo response*/
              handleICMP(sr, interface, packet, 0, 0);
            }
          }

          else
          /*Send ICMP destination port unreachable*/
          {
            handleICMP(sr, interface, packet, 3, 3);
          }
        }
        else
        {
          handleICMP(sr, interface, packet, 3, 0);
        }
      list = list->next;
    }

    if (selfIP != 0)
    {
      return;
    }

    printf("Not own IP\n");
    /*If TTL == 1, send ICMP TTL Exceeded*/
    if (ip_hd->ip_ttl == 1)
    {
      handleICMP(sr, interface, packet, 11, 0);
    }

    else
    {
      struct sr_rt *rt_match = longest_match(sr, ip_hd->ip_dst);

      if (rt_match == NULL)
      {
        /*Send ICMP destination network unreachable*/
        handleICMP(sr, interface, packet, 3, 0);
      }
      else
      {
        /*Change IP header TTL, checksum*/
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        send_ip_hdr->ip_ttl = send_ip_hdr->ip_ttl - 1;
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_sum = cksum(send_ip_hdr, sizeof(sr_ip_hdr_t));
        
        /*Change ethernet header: Source MAC, Destination MAC*/
        sr_ethernet_hdr_t *send_ethernet_hdr = (sr_ethernet_hdr_t *)packet;
        memcpy(send_ethernet_hdr->ether_shost, (sr_get_interface(sr, rt_match->interface)->addr), ETHER_ADDR_LEN);
        
         /*conditional statemet here takes care of no 2 in handle packet*/
        if(rt_match->gw.s_addr == 0)struct sr_arpentry *arp_entry = sr_arpcache_lookup((&sr->cache), ip_hd->ip_dst);
        else struct sr_arpentry *arp_entry = sr_arpcache_lookup((&sr->cache), rt_match->gw.s_addr);
        
        uint8_t *dest = arp_entry->mac;
        if (dest)
        {
          if(sr_obtain_interface_status(sr, interface))
          {
            /*Forward packet to destination*/
            memcpy(send_ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, rt_match->interface);
          }
          else
          {
            /*Send ICMP destination network unreachable*/
            handleICMP(sr, interface, packet, 3, 0);
          }
        }
        else
        {
          /*Send packet to arpcache*/
          /*conditional statemet here takes care of no 2 in handle packet*/
          if(rt_match->gw.s_addr == 0)sr_arpcache_queuereq(&sr->cache, ip_hd->ip_dst, packet, len, rt_match->interface);
          else sr_arpcache_queuereq(&sr->cache, rt_match->gw.s_addr, packet, len, rt_match->interface);
          
        }
      }
    }
  }
}
void sr_handleARP(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len, char *interface /* lent */)
{

  sr_ethernet_hdr_t ether_hdr;
  memcpy((uint8_t *)&ether_hdr, packet, sizeof(sr_ethernet_hdr_t));
  assert(ntohs(ether_hdr.ether_type) == ethertype_arp);
  sr_arp_hdr_t *arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *ether_hdr2 = (sr_ethernet_hdr_t *)packet;

  if (arp->ar_op == htons(arp_op_request))
  {

    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);
    printf("source mac:%d\n", arp->ar_sha);

    if (req)
    {
      struct sr_packet *p;
      for (p = req->packets; p != 0; p = p->next)
      {
        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)p->buf;
        memcpy(ether_hdr->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);

        struct sr_if *outgoing_if = sr_get_interface(sr, p->iface);
        assert(outgoing_if);
        memcpy(ether_hdr->ether_shost, outgoing_if->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, p->buf, p->len, p->iface);
      }
      sr_arpreq_destroy(&sr->cache, req);
    }

    /*CREATE ARP RESPONSE PACKET*/
    uint8_t *outgoing_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    struct sr_if *sr_if_resp = sr_get_interface(sr, interface);

    /*CREATE ETHERNET HEADER*/
    sr_ethernet_hdr_t *ether_hdr_resp = (sr_ethernet_hdr_t *)outgoing_packet;
    /*Ethernet packet type: ARP*/
    ether_hdr_resp->ether_type = htons(ethertype_arp);
    /*MAC addresses: Source and Destination*/
    memcpy(ether_hdr_resp->ether_shost, sr_if_resp->addr, sizeof(ether_hdr2->ether_dhost));
    memcpy(ether_hdr_resp->ether_dhost, arp->ar_sha, sizeof(arp->ar_sha));

    /*CREATE ARP HEADER*/
    sr_arp_hdr_t *arp_resp = (sr_arp_hdr_t *)(outgoing_packet + sizeof(sr_ethernet_hdr_t));
    /*Hardware address: format and length*/
    arp_resp->ar_hrd = htons(arp_hrd_ethernet);
    arp_resp->ar_hln = ETHER_ADDR_LEN;
    /*Protocol address: format and length*/
    arp_resp->ar_pro = htons(ethertype_ip);
    arp_resp->ar_pln = 4;
    /*ARP opcode: ARP reply*/
    arp_resp->ar_op = htons(arp_op_reply);
    /*IP Addresses: Source and Target*/
    arp_resp->ar_sip = sr_if_resp->ip;
    arp_resp->ar_tip = arp->ar_sip;
    /*MAC Addresses: Source and Target*/
    memcpy(arp_resp->ar_sha, sr_if_resp->addr, sizeof(sr_if_resp->addr));
    memcpy(arp_resp->ar_tha, arp->ar_sha, sizeof(arp->ar_sha));
    /*Send and free packet*/
    sr_send_packet(sr, outgoing_packet, len, interface);
    free(outgoing_packet);
  }
  else if ((arp->ar_op == htons(arp_op_reply)))
  {
    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);

    if (req)
    {
      struct sr_packet *p;
      for (p = req->packets; p != 0; p = p->next)
      {
        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)p->buf;
        memcpy(ether_hdr->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
        sr_send_packet(sr, p->buf, p->len, p->iface);
      }

      sr_arpreq_destroy(&sr->cache, req);
    }
  }
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

  /*printf("*** -> Received packet of length %d \n",len);*/

  if (len < sizeof(struct sr_ethernet_hdr_t *))
  {
    /*fprintf(stderr, "packet len is less than minimum ethernet heade\n");*/
  }
  assert(len >= sizeof(struct sr_ethernet_hdr));

  sr_ethernet_hdr_t ether_hdr;
  memcpy((uint8_t *)&ether_hdr, packet, sizeof(sr_ethernet_hdr_t));
  uint16_t pkt_type = ntohs(ether_hdr.ether_type);
  /*printf("packet type is %x\n", pkt_type);*/

  switch (pkt_type)
  {
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
}
