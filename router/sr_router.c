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

void handle_ip(uint8_t * packet) {
  printf("HANDLING IP\n");

  /* Parse the ethernet header */
  sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *) packet;
  printf("DEST MAC: ");      print_macaddr( eth_header->ether_dhost );
  printf("\nSRC MAC: "); print_macaddr( eth_header->ether_shost );
  
}

void handle_arp(uint8_t * packet) {
  int ETHERNET_HEADER_SIZE = 6 + 6 + 2;
  printf("HANDLING ARP\n");
  /* Parse the ethernet header */
  sr_ethernet_hdr_t * eth_header = (sr_ethernet_hdr_t *) packet;

  printf("DEST MAC: ");      print_macaddr( eth_header->ether_dhost );
  printf("\nSRC MAC: "); print_macaddr( eth_header->ether_shost );
  printf("\n");

  sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *)(packet + ETHERNET_HEADER_SIZE);  
  uint16_t ar_op = ntohs(arp_header->ar_op);
  if (ar_op == arp_op_request) {
    printf("ARP REQUEST\n");
  } else if (ar_op == arp_op_reply) {
    printf("ARP REPLY\n");
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

  printf("*** -> Received packet of length %d ",len);
  printf("on iface %s \n", interface);
  

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
      handle_arp(packet);
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

