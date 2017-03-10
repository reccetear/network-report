#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#define BUFFER_SEND 512

struct ICMP {
	unsigned char type;
	unsigned char code;
	unsigned short check_sum;
	unsigned short id;
	unsigned short sequence;
	unsigned long timestamp;
};

struct ARP {
	unsigned short Htype;		//Hardware Type
	unsigned short Ptype;		//Protocal Type
	unsigned char Mac_Length;
	unsigned char IP_Length;
	unsigned short OP;		//Operation Code
	unsigned char sender_Mac[6];
	unsigned char sender_IP[4];
	unsigned char recver_Mac[6];
	unsigned char recver_IP[4];
	char data[18];
};

unsigned short checksum(unsigned short* buff, int size);
