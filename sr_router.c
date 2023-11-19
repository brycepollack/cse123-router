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
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

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
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
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
 * FROM WRITEUP:
 * The router must successfully route ICMP messages between the client and the application servers.
 * The router must correctly handle ARP requests and replies.
 * The router must respond correctly to ICMP echo requests.
 * The router must send an ARP request for each packet it forwards.
 * The router must queue all packets waiting for outstanding ARP replies. If a host does not respond to an ARP request within 5 seconds, the queued packet is dropped and an ICMP host unreachable message is sent back to the source of the queued packet.
 * The router must not needlessly drop packets (for example, when waiting for an ARP reply).
 * The router must enforce guarantees on timeouts – if an ARP request is not responded to within a fixed period of time, the ICMP host unreachable message is generated even if no more packets arrive at the router.
 * 
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  /* Figure out if a packet is ip, arp, handle accordingly*/
  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_arp) { /* ARP */
    sr_handlearppacket(sr, packet, len, interface);
  }
  else if (ethtype == ethertype_ip) { /* IP */
    sr_handleippacket(sr, packet, len, interface);
  }
  else { /* ERROR */
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    return;
  }

}

void sr_handleippacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t dst_ip = iphdr->ip_dst;

  /*Sanity-check the packet (i.e., it meets minimum length and correct checksum). IP checksum is calculated over IP header*/
  /*
  Verify the IP header length - “ip_hl” (must be 20 bytes - refer to RFC791).
  Verify IP packet length - “ip_len” (must be greater than the IP header length).
  */
  int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  uint16_t incoming_ipcksum = iphdr->ip_sum;
  iphdr->ip_sum = 0;
  iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
  if (len < minlength || iphdr->ip_sum != incoming_ipcksum || iphdr->ip_hl != 5 || iphdr->ip_hl > ntohs(iphdr->ip_len)) {
    fprintf(stderr, "Failed to handle IP, insufficient length or invalid checksum\n");
    return;
  }

  /*Handle ip packet*/

  /*Check if packet is destined towards one of the router interfaces*/
  struct sr_if* if_walker = sr->if_list;
  struct sr_if* dst_if = NULL;
  while(if_walker) {
    if(if_walker->ip == dst_ip){ 
      dst_if = if_walker;
      break;
    }
    if_walker = if_walker->next;
  }

  /*
  If the frame contains an IP packet that is NOT destined towards one of the router interfaces: 
  Decrement the TTL by 1, and recompute the packet checksum over the modified header
  Find an entry in the routing table that exactly matches the destination IP address
  If an entry exists, send an ARP request for the next-hop IP
  If no entry exists or if an ARP response is not received, send an ICMP destination unreachable message back to source of packet
  */

  /*
  If packet is destined towards one of the router interfaces: 
  If packet is ICMP echo request and checksum is valid, send ICMP echo reply to sending host
  Otherwise, ignore the packet
  */

  if(dst_if == NULL){ /*NOT destined towards one of the router interfaces*/
    fprintf(stderr, "sr_handleippacket: NOT destined towards one of the router interfaces\n");
    /*Decrement the TTL by 1, and recompute the packet checksum over the modified header*/
    iphdr->ip_ttl -= 1;
    /*Refuse any TTL <= 0*/
    if(iphdr->ip_ttl <= 0){
      fprintf(stderr, "Failed to handle IP packet, TTL expired\n");
      /*Send icmp type 11 code 0*/
      sr_sendicmppacket(sr, packet, len, interface, 11, 0);
      return;
    }
    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

    /*Find an entry in the routing table that exactly matches the destination IP address*/
    struct sr_rt* rt_walker = sr->routing_table;
    struct sr_rt* dst_rt_entry = NULL;
    while(rt_walker) {
      if(rt_walker->dest.s_addr == dst_ip){
        dst_rt_entry = rt_walker;
        break;
      }
      rt_walker = rt_walker->next;
    }

    if(dst_rt_entry != NULL){
      /*Send an ARP request for the next-hop IP*/
      fprintf(stderr, "Incoming packet IP, sending arp req to next hop router\n");
      struct sr_arpreq *arpreq = sr_arpcache_queuereq(&(sr->cache), dst_rt_entry->gw.s_addr, packet, len, dst_rt_entry->interface);
      sr_handlearpreq(sr, &(sr->cache), arpreq);
    }
    else{
      /*Send icmp type 3 code 0*/
      fprintf(stderr, "Incoming packet IP, no matching next hop found\n");
      sr_sendicmppacket(sr, packet, len, interface, 3, 0);
    }
  }
  else{ /*destined towards one of the router interfaces*/
    fprintf(stderr, "Incoming packet IP, destined towards one of the router interfaces\n");
    if(ip_protocol(packet + sizeof(sr_ethernet_hdr_t)) == ip_protocol_icmp) { /* ICMP */
      sr_handleicmppacket(sr, packet, len, interface);
    }

  }

}

void sr_handleicmppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_icmp_t11_hdr_t *icmp11hdr = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  if (icmp11hdr->icmp_type == 8) { /*Echo request*/
    sr_icmp_t08_hdr_t *icmp08hdr = (sr_icmp_t08_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /*Sanity-check the packet (i.e., it meets minimum length and correct checksum). ICMP checksum is calculated over ICMP header*/
    int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 4; /*print_hdrs uses 4 for icmp min length, not sure why*/
    uint16_t incoming_icmpcksum = icmp08hdr->icmp_sum;
    icmp08hdr->icmp_sum = 0;
    icmp08hdr->icmp_sum = cksum(icmp08hdr, len - minlength + 4);
    if (len < minlength || icmp08hdr->icmp_sum != incoming_icmpcksum){
      fprintf(stderr, "Failed to handle ICMP, insufficient length or invalid checksum\n");
      return;
    }

    fprintf(stderr, "Incoming packet ICMP echo request, sending echo reply\n");
    /*Send icmp type 0 code 0*/
    sr_sendicmppacket(sr, packet, len, interface, 0, 0);

  }

}

void sr_handlearppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /*Sanity-check the packet (i.e., it meets minimum length)*/
  int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  if (len < minlength){
    fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    return;
  }

  if(ntohs(arphdr->ar_op) == arp_op_request){ /*Request*/
    fprintf(stderr, "Incoming packet ARP req\n");
    /*Send arp reply when target IP address is the IP address of the router’s interface that the ARP request was received on*/
    if(arphdr->ar_tip == sr_get_interface(sr, interface)->ip){
      sr_sendarppacket(sr, packet, len, interface, 2, arphdr->ar_sip);
    }
    
  }
  else if(ntohs(arphdr->ar_op) == arp_op_reply){ /*Reply*/
    fprintf(stderr, "Incoming packet ARP reply\n");
    /*Forward queued packets waiting on this reply*/
    struct sr_arpreq *waiting_req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, arphdr->ar_sip);
    if(waiting_req == NULL){
      fprintf(stderr, "Failed to process ARP reply\n");
      return;
    }

    struct sr_packet *packet_walker = waiting_req->packets;
    while(packet_walker){
      uint8_t *new_packet = packet_walker->buf;
      unsigned int new_len = packet_walker->len;
      sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *)(new_packet);
      memcpy(new_ethhdr->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(new_ethhdr->ether_shost, sr_get_interface(sr, packet_walker->iface)->addr, ETHER_ADDR_LEN);

      fprintf(stderr, "Received arp reply, forwarding original packet to\n");
      sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
      print_addr_ip_int(ntohl(iphdr->ip_dst));
      sr_send_packet(sr, new_packet, new_len, packet_walker->iface);

      packet_walker = packet_walker->next;
    }
    sr_arpreq_destroy(&(sr->cache), waiting_req);

  }

}

void sr_sendicmppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        uint8_t icmp_type,
        uint8_t icmp_code)
{

  /*
  Handle the following:
  type 0 code 0: echo reply
  type 3 code 0: destination net unreachable
  type 3 code 1: destination host unreachable
  type 11 code 0: time exceeded
  */

  if(icmp_type == 0){ /*echo reply, contains a copy of the echo request’s body*/
    /*Ethernet header*/
    sr_ethernet_hdr_t *ethhdr = (sr_ethernet_hdr_t *)(packet);
    uint8_t temp_ether_dhost[ETHER_ADDR_LEN];
    memcpy(temp_ether_dhost, ethhdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(ethhdr->ether_dhost, ethhdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethhdr->ether_shost, temp_ether_dhost, ETHER_ADDR_LEN);
    ethhdr->ether_type = htons(ethertype_ip);
    /*IP Header*/
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t dst_ip = iphdr->ip_dst;
    uint32_t src_ip = iphdr->ip_src;
    iphdr->ip_ttl = INIT_TTL;
    iphdr->ip_sum = 0;
    iphdr->ip_dst = src_ip;
    iphdr->ip_src = dst_ip;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
    /*ICMP Header*/
    sr_icmp_t08_hdr_t *icmp08hdr = (sr_icmp_t08_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp08hdr->icmp_type = icmp_type;
    icmp08hdr->icmp_code = icmp_code;
    icmp08hdr->icmp_sum = 0;
    icmp08hdr->icmp_sum = cksum(icmp08hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    fprintf(stderr, "Sending ICMP echo reply to\n");
    print_addr_ip_int(ntohl(iphdr->ip_dst));
    sr_send_packet(sr, packet, len, interface);
  }
  else{ /*icmp error, contains the original IP header + 8 bytes*/
    /*Create new packet*/
    unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t *new_packet = (uint8_t *)malloc(new_len);

    /*Ethernet header*/
    sr_ethernet_hdr_t *old_ethhdr = (sr_ethernet_hdr_t *)(packet);
    sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *)(new_packet);
    uint8_t temp_ether_dhost[ETHER_ADDR_LEN];
    memcpy(temp_ether_dhost, old_ethhdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(new_ethhdr->ether_dhost, old_ethhdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_ethhdr->ether_shost, temp_ether_dhost, ETHER_ADDR_LEN);
    new_ethhdr->ether_type = htons(ethertype_ip);
    /*IP Header*/
    sr_ip_hdr_t *old_iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *new_iphdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    uint32_t dst_ip = old_iphdr->ip_dst;
    uint32_t src_ip = old_iphdr->ip_src;
    memcpy(new_iphdr, old_iphdr, sizeof(sr_ip_hdr_t));
    new_iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    new_iphdr->ip_ttl = INIT_TTL;
    new_iphdr->ip_sum = 0;
    new_iphdr->ip_dst = src_ip;
    new_iphdr->ip_src = dst_ip;
    new_iphdr->ip_sum = cksum(new_iphdr, sizeof(sr_ip_hdr_t));
    /*ICMP Header*/
    sr_icmp_t11_hdr_t *new_icmp11hdr = (sr_icmp_t11_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp11hdr->icmp_type = icmp_type;
    new_icmp11hdr->icmp_code = icmp_code;
    new_icmp11hdr->icmp_sum = 0;
    memset(new_icmp11hdr->data, 0, 28);
    if(len > new_len){
      memcpy(new_icmp11hdr->data, old_iphdr, ICMP_DATA_SIZE);
    }
    else{
      memcpy(new_icmp11hdr->data, old_iphdr, sizeof(sr_ip_hdr_t));
    }
    new_icmp11hdr->icmp_sum = cksum(new_icmp11hdr, sizeof(sr_icmp_t11_hdr_t));

    fprintf(stderr, "Sending ICMP error type %d code %d to\n", icmp_type, icmp_code);
    print_addr_ip_int(ntohl(new_iphdr->ip_dst));
    sr_send_packet(sr, new_packet, new_len, interface);
    free(new_packet);
  }

}

void sr_sendarppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */,
        uint8_t arp_op,
        uint32_t target_ip)
{

  /*Send request when forwarding a packet*/
  /*Send reply when target IP address is the IP address of the router’s interface that the ARP request was received on*/

  if(arp_op == 1){ /*Handle send arp request*/
    /*Create new packet*/
    unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *new_packet = (uint8_t *)malloc(new_len);

    /*Ethernet Header*/
    sr_ethernet_hdr_t *new_ethhdr = (sr_ethernet_hdr_t *)(new_packet);
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; i++){
      new_ethhdr->ether_dhost[i] = 0xFF;
    }
    memcpy(new_ethhdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    new_ethhdr->ether_type = htons(ethertype_arp);
    /*ARP Header*/
    sr_arp_hdr_t *new_arphdr = (sr_arp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_arphdr->ar_hrd = htons(arp_hrd_ethernet);
    new_arphdr->ar_pro = htons(ethertype_ip);             
    new_arphdr->ar_hln = ETHER_ADDR_LEN;             
    new_arphdr->ar_pln = 4; /*uint32_t*/            
    new_arphdr->ar_op = htons(arp_op_request);
    memcpy(new_arphdr->ar_sha, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    new_arphdr->ar_sip = sr_get_interface(sr, interface)->ip;
    new_arphdr->ar_tip = target_ip;
    for(i = 0; i < ETHER_ADDR_LEN; i++){
      new_arphdr->ar_tha[i] = 0x00;
    }
    fprintf(stderr, "Sending ARP req to\n");
    print_addr_ip_int(ntohl(new_arphdr->ar_tip));

    sr_send_packet(sr, new_packet, new_len, interface);
    free(new_packet);
  }
  else if(arp_op == 2){ /*Handle send arp reply*/
    /*Ethernet header*/
    sr_ethernet_hdr_t *ethhdr = (sr_ethernet_hdr_t *)(packet);
    memcpy(ethhdr->ether_dhost, ethhdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethhdr->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    ethhdr->ether_type = htons(ethertype_arp);
    /*ARP Header*/
    sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));           
    arphdr->ar_op = htons(arp_op_reply);
    memcpy(arphdr->ar_sha, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    arphdr->ar_sip = sr_get_interface(sr, interface)->ip;
    memcpy(arphdr->ar_tha, ethhdr->ether_shost, ETHER_ADDR_LEN);
    arphdr->ar_tip = target_ip;
    
    fprintf(stderr, "Sending ARP reply to\n");
    print_addr_ip_int(ntohl(arphdr->ar_tip));
    sr_send_packet(sr, packet, len, interface);
  }
  

}

