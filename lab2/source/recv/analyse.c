#include "socket_head.h"

void analyse_IP(char *IP_buffer)
{
	struct IP *ip_datagram1 = (void *)IP_buffer;
	printf("IP Version : %d\t",ip_datagram1->version);
	printf("IP Internet Head Length : %d\n\t",ip_datagram1->IHL);
	printf("IP Source Address : %d.%d.%d.%d\n\t",ip_datagram1->SA[0],ip_datagram1->SA[1],ip_datagram1->SA[2],ip_datagram1->SA[3]);
	printf("IP Destination Address : %d.%d.%d.%d\n\t",ip_datagram1->DA[0],ip_datagram1->DA[1],ip_datagram1->DA[2],ip_datagram1->DA[3]);
	printf("IP Protocal : \t");
	switch(ip_datagram1->proto)
	{
		case IPPROTO_ICMP:printf("ICMP\n\t");break;
		case IPPROTO_IGMP:printf("IGMP\n\t");break;
		case IPPROTO_IPIP:printf("IPIP\n\t");break;
		case IPPROTO_TCP:printf("TCP\n\t");break;
		case IPPROTO_UDP:printf("UDP\n\t");break;
		default : printf("Need to add query\n\t");
	}
	printf("IP Lives : %d(s)\n",ip_datagram1->live);
	return;
}

void analyse_ARP(char *ARP_buffer)
{
	struct ARP *arp_packet1 = (void *)ARP_buffer;
	printf("Mac length : %d\n\t",arp_packet1->Mac_Length);
	printf("IP length : %d\n\t",arp_packet1->IP_Length);
	switch(arp_packet1->OP)
	{
		case 1:printf("Type : Request\n\t");
		case 2:printf("Type : Reply\n\t");
		default:printf("No type\n\t");
	}
	printf("Sender Mac Address : %02x:%02x:%02x:%02x:%02x:%02x\n\t",arp_packet1->sender_Mac[0],arp_packet1->sender_Mac[1],arp_packet1->sender_Mac[2],arp_packet1->sender_Mac[3],arp_packet1->sender_Mac[4],arp_packet1->sender_Mac[5]);
	printf("Sender IP Address : %d.%d.%d.%d\n\t",arp_packet1->sender_IP[0],arp_packet1->sender_IP[1],arp_packet1->sender_IP[2],arp_packet1->sender_IP[3]);
	printf("Recver Mac Address : %02x:%02x:%02x:%02x:%02x:%02x\n\t",arp_packet1->recver_Mac[0],arp_packet1->recver_Mac[1],arp_packet1->recver_Mac[2],arp_packet1->recver_Mac[3],arp_packet1->recver_Mac[4],arp_packet1->recver_Mac[5]);
	printf("Recver IP Address : %d.%d.%d.%d\n",arp_packet1->recver_IP[0],arp_packet1->recver_IP[1],arp_packet1->recver_IP[2],arp_packet1->recver_IP[3]);
	return;
}

void analyse_RARP(char *RARP_buffer)
{
	struct ARP *rarp_packet1 = (void *)RARP_buffer;
	printf("Mac length : %d\n\t",rarp_packet1->Mac_Length);
	printf("IP length : %d\n\t",rarp_packet1->IP_Length);
	switch(rarp_packet1->OP)
	{
		case 3:printf("Type : Request\n\t");
		case 4:printf("Type : Reply\n\t");
		default:printf("No type\n\t");
	}
	printf("Sender Mac Address : %02x:%02x:%02x:%02x:%02x:%02x\n\t",rarp_packet1->sender_Mac[0],rarp_packet1->sender_Mac[1],rarp_packet1->sender_Mac[2],rarp_packet1->sender_Mac[3],rarp_packet1->sender_Mac[4],rarp_packet1->sender_Mac[5]);
	printf("Sender IP Address : %d.%d.%d.%d\n\t",rarp_packet1->sender_IP[0],rarp_packet1->sender_IP[1],rarp_packet1->sender_IP[2],rarp_packet1->sender_IP[3]);
	printf("Recver Mac Address : %02x:%02x:%02x:%02x:%02x:%02x\n\t",rarp_packet1->recver_Mac[0],rarp_packet1->recver_Mac[1],rarp_packet1->recver_Mac[2],rarp_packet1->recver_Mac[3],rarp_packet1->recver_Mac[4],rarp_packet1->recver_Mac[5]);
	printf("Recver IP Address : %d.%d.%d.%d\n",rarp_packet1->recver_IP[0],rarp_packet1->recver_IP[1],rarp_packet1->recver_IP[2],rarp_packet1->recver_IP[3]);
	return;
}
