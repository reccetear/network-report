#ifndef __ROUTE_H__
#define __ROUTE_H__

#define MAX_ROUTE_INFO 10
#define MAX_ARP_SIZE 10
#define MAX_DEVICE 10
#define MAX_BUFFER_SIZE 2048
#define ETHER_IP 0x0800
#define ETHER_ARP 0x0806
#define ARP_REQUEST 0x1
#define ARP_REPLY 0x2
#define PACK 100
#define UNPACK 101


typedef struct ethernet {
	unsigned char dst[6];
	unsigned char src[6];
	unsigned char type[2];
} eth_head;

typedef struct IP {
	unsigned char IHL : 4;			//Internet Head Length
	unsigned char version : 4;		//IP Version
	unsigned char ECN : 2;
	unsigned char DS : 6;			//Determine Service
	unsigned short length;			//Length of datagram
	unsigned short label;
	unsigned short offset : 13;
	unsigned char tag : 3;
	unsigned char live;
	unsigned char protocol;
	unsigned short check_sum;
	unsigned char ip_src[4];		//Source Address
	unsigned char ip_dst[4];		//Destination Address
} ip_head;

typedef struct ICMP {
	unsigned char type;
	unsigned char code;
	unsigned short check_sum;
	unsigned short id;
	unsigned short sequence;
	unsigned long timestamp;
} icmp_head;

typedef struct ARP {
	unsigned char mac_target[6];
	unsigned char mac_source[6];
	unsigned short ethertype;
	unsigned short hw_type;
	unsigned short proto_type;
	unsigned char mac_addr_len;
	unsigned char ip_addr_len;
	unsigned short op;
	unsigned char mac_sender[6];
	unsigned char ip_sender[4];
	unsigned char mac_receiver[6];
	unsigned char ip_receiver[4];
	unsigned char padding[18];
} arp_head;

typedef struct VPN_route {
	unsigned char dst[16];
	unsigned char VPN_dst[16];
	unsigned char netmask[16];
} VPN_item;

typedef struct route_item {
	unsigned char destination[16];
	unsigned char gateway[16];
	unsigned char netmask[16];
	unsigned char interface[16];
} route_item;

typedef struct arp_item {
	unsigned char ip_addr[16];
	unsigned char mac_addr[18];
} arp_item;

typedef struct device_item {
	unsigned char interface[16];
	unsigned char ip_addr[16];
	unsigned char mac_addr[18];
	int is_entrance;
} device_item;

VPN_item VPN_route_info[MAX_ROUTE_INFO];
int VPN_item_index = 0;
route_item route_info[MAX_ROUTE_INFO];
int route_item_index = 0;
arp_item arp_table[MAX_ARP_SIZE];
int arp_item_index = 0;
device_item device[MAX_DEVICE];
int device_item_index = 0;

#endif
