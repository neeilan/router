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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

int MAC_ADDR_SIZE = 6;
int ETHERNET_HEADER_SIZE = 6 + 6 + 2;

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

/*

*/
void handle_arp_request(
  struct sr_instance * sr,
  struct sr_if * iface,
  sr_arp_hdr_t * hdr) {

  uint32_t target_ip = hdr->ar_tip;
  struct sr_arpentry * entry = sr_arpcache_lookup( &sr->cache, target_ip );

  if (entry == NULL) {
    /* No ARP entry - drop */
    return;
  }

  /* Many of the fields are the same as the ARP request, so just memcpy
     and modify the following fields, which differ:
     - opcode (request -> reply)
     - sender MAC and IP
     - target protocol and IP
  */
  sr_arp_hdr_t reply;
  memcpy(&reply, hdr, sizeof(reply));

  reply.ar_op = htons(arp_op_reply); 
  /* Everything else was memcpy'd from network, so no need for hton* */
  reply.ar_sip = iface->ip;
  reply.ar_tip = hdr->ar_sip; /* Back to source */
  memcpy(&reply.ar_sha, iface->addr, MAC_ADDR_SIZE);
  memcpy(&reply.ar_tha, hdr->ar_sha, MAC_ADDR_SIZE);

  /* Ethernet frame */
  send_ethernet_frame(
    sr,
    (uint8_t*) &reply,
    sizeof(reply),
    reply.ar_tip,
    iface->name,
    ethertype_arp);
}

void handle_arp_reply(sr_arp_hdr_t * hdr) {
 /*
  req - arpcache_insert(ip, mac)
  if req:
    
    arpreq_destroit(req)
  */ 
  
}

struct sr_rt * match_longest_prefix(struct sr_instance * sr, uint32_t ip_addr) {
  struct sr_rt * longest_match = NULL;
  int longest_prefix = 0;

  ip_addr = ntohl(ip_addr);

  struct sr_rt * rt = sr->routing_table;
  while (rt) {
    int curr_prefix = 0;
    uint32_t prefix = 1 << 31;
    uint32_t mask = 0;    


    /* Exact match baby! */
    if (ip_addr == ntohl(rt->dest.s_addr)) { 
      return rt;
    }

    while ( (ip_addr & mask) == (ntohl(rt->dest.s_addr) & mask) ) {
      if (curr_prefix > longest_prefix) {
        longest_prefix = curr_prefix;
        longest_match = rt;
      }

      mask = mask | prefix;
      prefix = ( prefix >> 1 ) | ( 1 << 31 );
      curr_prefix++;

    }
    
    rt = rt->next;
  }

  return longest_match; 
}


void send_ip_datagram(
    struct sr_instance * sr,
    struct sr_rt * rt,
    sr_ip_hdr_t * data,
    size_t data_size) {
  send_ethernet_frame(sr, data, data_size, rt->dest.s_addr, rt->interface, ethertype_ip);
}

/*
Sends a black-box packet (data) of size data_size bytes as an ethernet
frame to rt link.
*/
void send_ethernet_frame(
  struct sr_instance * sr,
  uint8_t * data,
  size_t data_size,
  uiint8_t * dest_addr.
  const char * interface,
  uint8_t ethertype) {

  size_t eth_frame_size = sizeof(sr_ethernet_hdr_t) + data_size;
  uint8_t * buffer = malloc(eth_frame_size);

  struct sr_if * iface = sr_get_interface(sr, interface);
  if (!iface) { return; }

  sr_ethernet_hdr_t * eth_hdr_borrowed = (sr_ethernet_hdr_t*) buffer;
  memcpy(eth_hdr_borrowed->ether_dhost, dest_addr, ETHER_ADDR_LEN);
  memcpy(eth_hdr_borrowed->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr_borrowed->ether_type = htons(ethertype);

  memcpy(eth_hdr_borrowed + 1, data, data_size);
  sr_send_packet(sr, buffer, eth_frame_size, rt->interface );
  free(buffer);
}

void send_icmp(
  struct sr_instance * sr,
  sr_ip_hdr_t * ip_hdr,
  uint8_t icmp_type,
  uint8_t icmp_code) {

  int len = sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t) + 8;  
  uint8_t* buffer = (uint8_t*) malloc( len );

  sr_icmp_hdr_t * icmp_hdr_borrowed = (sr_icmp_hdr_t *) buffer;
  icmp_hdr_borrowed->icmp_type = icmp_type;
  icmp_hdr_borrowed->icmp_code = icmp_code;

  /* Calculate checksum */
  icmp_hdr_borrowed->icmp_sum = 0;
  icmp_hdr_borrowed->icmp_sum = cksum( icmp_hdr_borrowed, sizeof(sr_icmp_hdr_t) );

  memcpy(buffer + sizeof(sr_icmp_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t) + 8);

  uint8_t * dest_addr = ip_hdr->sip;

  send_ethernet_frame(sr, buffer, len, dest_addr  interface, ethertype_ip);
  free(buffer);
}

/* Per the RFC, "the internet header plus the first 8 bytes of the original datagram's data is returned to the sender."*/
void send_icmp_ttl(struct sr_instance * sr, sr_ip_hdr_t * ip_hdr) {
  /* Reference for codes: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages */
  send_icmp(sr, ip_hdr, 11, 0);
}

/* Handles IP requests. */
void handle_ip(struct sr_instance * sr, uint8_t * eth_packet) {
  /* Parse the ethernet header */
  /*sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *) eth_packet;*/
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (eth_packet + sizeof(sr_ethernet_hdr_t));

  /* According to Wikipedia, "IHL field contains the size of the IPv4 header,
  it has 4 bits that specify the number of 32-bit words in the header."; so 
  we multiply this value by 4 to get total size in bytes */
  unsigned int ip_hl = ip_hdr->ip_hl;

  /* Verify the checksum */
  sr_ip_hdr_t * buf = (sr_ip_hdr_t *) malloc(sizeof(uint32_t) * ip_hl);
  memcpy(buf, ip_hdr, sizeof(uint32_t) * ip_hl);
  /* Clear checksum in frame before calculating checksum. So no recursion :) */
  buf->ip_sum = 0;

  uint16_t calculated_cksum = cksum((const void * )buf, 4 * ip_hl);
  free(buf);

  if (calculated_cksum != ip_hdr->ip_sum) {
    fprintf(stderr, "IP checksum incorrect - dropping packet.\n");
    return; 
  }

  const uint32_t dst_ip = htonl(ip_hdr->ip_dst);

  /* Check whether this packet is for one of my interfaces. */
  struct sr_if * iface = sr->if_list;
  while (iface && htonl(iface->ip) != dst_ip) {
    iface = iface->next;
  }

  if (iface) {
    /* This is for me. */  
    return;
  }

  uint8_t next_ttl;
  if ((next_ttl = ip_hdr->ip_ttl - 1) == 0) {
    printf("Ran out of TTL - send ICMP.\n");
    return;
  }

  
  sr_ip_hdr_t * res_ip_hdr = (sr_ip_hdr_t *) malloc(sizeof(sr_ip_hdr_t));
  memcpy(res_ip_hdr, ip_hdr, sizeof(sr_ip_hdr_t));

  /* Set fields in the response IP datagram. */
  res_ip_hdr->ip_ttl = next_ttl;
  
  /* Calculate the checksum */
  res_ip_hdr->ip_sum = 0;
  res_ip_hdr->ip_sum = cksum((const void *) res_ip_hdr, ip_hl * 4);
  
  /* Find the appropriate router (if any) to forward to. */
  struct sr_rt * match = match_longest_prefix(sr, ip_hdr->ip_dst); 
  if (match) {
    int ip_packet_len = ntohs(ip_hdr->ip_len) ;
    
    uint8_t * buffer = (uint8_t*) malloc( sizeof(uint8_t) * ip_packet_len ); 
    /* Copy the header */
    memcpy(buffer, res_ip_hdr, ip_hl * 4);

    /* Copy the data */
    memcpy(((uint8_t *)buffer) + sizeof(sr_ip_hdr_t),
      ((uint8_t*)ip_hdr) + sizeof(sr_ip_hdr_t),
      ip_packet_len - sizeof(sr_ip_hdr_t));

    /* Send it! */

    send_ip_datagram(sr, match, (sr_ip_hdr_t *) buffer, ip_packet_len); 

    free(buffer);
  } else {
    /* No match found */
  }

  free(res_ip_hdr);
}


/*---------------------------------------------------------------------
  Handles ARP (requests and replies). In turn, it uses
  handle_arp_request and handle_arp_reply to do its work.
  uint8_t * packet is pointer to start of the ethernet packet.
---------------------------------------------------------------------*/
void handle_arp(
  struct sr_instance * sr,
  struct sr_if * iface,
  uint8_t * packet) {
  /* Parse the ethernet header */
  sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *) packet;
  sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *)(packet + ETHERNET_HEADER_SIZE);  

  uint32_t arp_tip = arp_header->ar_tip;
  struct sr_if *  curr_iface = sr->if_list;
  /* First check if this is for any of my interface */
  /* TODO(neeilan): Put own entries in cache so we can remove this code path */
  while (curr_iface && curr_iface->ip != arp_tip) {
    curr_iface = curr_iface->next;
  }
  if (curr_iface) {
    /* If so, send the receiving interface MAC back, because that's where
       the sender should send future requests to target IP to. */

    sr_arp_hdr_t reply;
    memcpy(&reply, arp_header, sizeof(reply));
    reply.ar_op = htons(arp_op_reply); 
    reply.ar_sip = iface->ip;
    reply.ar_tip = arp_header->ar_sip; /* Back to source */
    memcpy(&reply.ar_sha, iface->addr, ETHER_ADDR_LEN);
    memcpy(&reply.ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);

    /*  ========================
     * | ETHERNET HDR | ARP HDR | 
     *  ========================
     */
    const int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * reply_buff = (uint8_t*) malloc(packet_len);


    send_ethernet_frame(
      sr,
      &reply,
      sizeof(reply),
      eth_header->ether_shost,
      iface->name,
      ethertype_arp);

    return;
    
  } else {
    printf("ARP req not for me or anyone I know; dropping.\n");
    return;
  }


  uint16_t ar_op = ntohs(arp_header->ar_op);
  if (ar_op == arp_op_request) {
    handle_arp_request(sr, iface, arp_header);
  } else if (ar_op == arp_op_reply) {
    printf("ARP REPLY\n");
    handle_arp_reply(arp_header);
  } else {
    /* ERROR - ignore */
  }
}


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
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  if (len < sizeof(sr_ethernet_hdr_t)) {
    /* Packet too small - drop */
    return;
  }


  struct sr_if * iface = sr_get_interface(sr, interface);

  switch (ethertype(packet)) {
    /* If the packet is too small to be ARP / IP, just drop it. */
    case ethertype_arp: {
      if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) return;
      handle_arp(sr, iface, packet);
      return;
    }
    case ethertype_ip: {
      if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;
      handle_ip(sr, packet);
      return;
    }
    default: {
      /* DROP */
    }
  }

}/* end sr_ForwardPacket */

