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
uint8_t * read_macaddr(uint8_t * ptr) {
  uint8_t * buff = (uint8_t*) malloc( sizeof(uint8_t) * 7);
  buff[6] = '\0';
  return buff;
}

void print_macaddr(uint8_t * ptr) {
  uint8_t * mac = read_macaddr(ptr);
  printf("%d:%d:%d:%d:%d:%d", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  free(mac);
}

void print_ip(uint32_t ip) {
  printf("%hhu.%hhu.%hhu.%hhu",
    *((uint8_t*)(&ip)),
    *(((uint8_t*)&ip) + 1 ), 
    *(((uint8_t*)&ip) + 2 ), 
    *(((uint8_t*)&ip) + 3 ));
}

void handle_arp_request(
  struct sr_instance * sr,
  struct sr_if * iface,
  sr_arp_hdr_t * hdr) {

  
  printf("\nARP REQ sender sha is "); print_macaddr( hdr->ar_sha );
  printf("and tha is "); print_macaddr( hdr->ar_tha );
  printf("\n");

  uint32_t target_ip = hdr->ar_tip;
  uint32_t sender_ip = hdr->ar_sip;

  printf("ARP REQ sender ip is "); print_ip(sender_ip); printf("\n");

  struct sr_arpentry * entry = sr_arpcache_lookup( &sr->cache, target_ip );

  if (entry == NULL) {
    /* No ARP entry */
    printf("No ARP entry for IP: ");
    print_ip(target_ip);
    printf("\n");
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
  
  

}

void handle_arp_reply(sr_arp_hdr_t * hdr) {
 /*
  req - arpcache_insert(ip, mac)
  if req:
    
    arpreq_destroit(req)
  */ 
  
}

void handle_ip(uint8_t * packet) {
  printf("HANDLING IP\n");

  /* Parse the ethernet header */
  sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *) packet;
  printf("DEST MAC: ");  print_macaddr( eth_header->ether_dhost );
  printf("\nSRC MAC: "); print_macaddr( eth_header->ether_shost );
  
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) packet + ETHERNET_HEADER_SIZE;
  printf("Received IP req from addr: "); print_ip(ip_hdr->ip_src);
  printf(" to addr: "); print_ip(ip_hdr->ip_dst);
  printf("\n");
}

void handle_arp(
  struct sr_instance * sr,
  struct sr_if * iface,
  uint8_t * packet) {
  printf("HANDLING ARP\n");
  print_macaddr((uint8_t*)iface->addr);
  /* Parse the ethernet header */
  sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *) packet;

  printf("DEST MAC: ");      print_macaddr( eth_header->ether_dhost );
  printf("\nSRC MAC: "); print_macaddr( eth_header->ether_shost );
  printf("\n");

  sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *)(packet + ETHERNET_HEADER_SIZE);  

  uint32_t arp_tip = arp_header->ar_tip;
  struct sr_if *  curr_iface = sr->if_list;
  /* First check if this is for any of my interface */
  while (curr_iface && curr_iface->ip != arp_tip) {
    curr_iface = curr_iface->next;
  }
  if (curr_iface) {
    /* If so, send the receiving interface MAC back, because that's where
       the sender should send future requests to target IP to. */
    printf("ARP req is for one of my interfaces!\n");
    sr_arp_hdr_t reply;
    memcpy(&reply, arp_header, sizeof(reply));
    reply.ar_op = htons(arp_op_reply); 
    /* Everything else was memcpy'd from network, so no need for hton* */
    reply.ar_sip = iface->ip;
    reply.ar_tip = arp_header->ar_sip; /* Back to source */
    memcpy(&reply.ar_sha, iface->addr, MAC_ADDR_SIZE);
    memcpy(&reply.ar_tha, arp_header->ar_sha, MAC_ADDR_SIZE);

    int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * reply_buff = (uint8_t*) malloc(packet_len);
    sr_ethernet_hdr_t * reply_eth_hdr = (sr_ethernet_hdr_t*) reply_buff;
    memcpy(&reply_eth_hdr->ether_dhost, eth_header->ether_shost, MAC_ADDR_SIZE);
    memcpy(&reply_eth_hdr->ether_shost, iface->addr, MAC_ADDR_SIZE);
    print_macaddr((uint8_t*)&reply_eth_hdr->ether_shost);
    reply_eth_hdr->ether_type = htons(ethertype_arp);
    


    memcpy(reply_buff + sizeof(sr_ethernet_hdr_t), &reply, sizeof(sr_arp_hdr_t));
    int res = sr_send_packet(sr, reply_buff, packet_len, iface->name); 
  
    free(reply_buff);
    


    return;
    
  } else {
    printf("ARP req not for me or anyone I know; dropping.\n");
    return;
  }


  uint16_t ar_op = ntohs(arp_header->ar_op);
  if (ar_op == arp_op_request) {
    printf("ARP REQUEST\n");
    handle_arp_request(sr, iface, arp_header);
  } else if (ar_op == arp_op_reply) {
    printf("ARP REPLY\n");
    handle_arp_reply(arp_header);
  } else {
    /* ERROR - ignore */
  }
}


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /*

  struct sr_instance
  {
    int  sockfd;                 socket to server 
    char user[32];               user name 
    char host[32];               host name  
    char template[30];           template name if any 
    unsigned short topo_id;
    struct sockaddr_in sr_addr;  address to server 
    struct sr_if if_list;        list of interfaces 
    struct sr_rt routing_table;  routing table 
    struct sr_arpcache cache;    ARP cache 
    pthread_attr_t attr;
    FILE* logfile;
  };
	*/


  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_if * iface = (struct sr_if *) interface;

  printf("\n\n*** -> Received packet of length %d ",len);
  printf("on iface %s (", interface); print_macaddr((uint8_t*)iface->addr); printf(")\n");
  

  /*

  uint16_t cksum(const void *_data, int len);

  uint16_t ethertype(uint8_t *buf);
  uint8_t ip_protocol(uint8_t *buf);

  void print_addr_eth(uint8_t *addr);
  void print_addr_ip(struct in_addr address);
  void print_addr_ip_int(uint32_t ip);

  void print_hdr_eth(uint8_t *buf);

  */

  switch (ethertype(packet)) {
    case ethertype_arp: {
      handle_arp(sr, iface, packet);
      return;
    }
    case ethertype_ip: {
      handle_ip(packet);
      return;
    }
    default: {
      /* DROP */
    }
  }

}/* end sr_ForwardPacket */

