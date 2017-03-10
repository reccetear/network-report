#include "socket_head.h"

int main(int argc, char *argv[]) 
{
	int socket_fd;
	if((socket_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		printf("Error create raw socket!\n");
		return -1;
	}
	
	char buffer[BUFFER_MAX];
	while(1) 
	{
		int n_read = recvfrom(socket_fd,buffer,2048,0,NULL,NULL);
		if(n_read < 42)
		{
			printf("Error when recieve message!\n");
			return -1;
		}

		struct Ethernet *ethernet_frame1 = (void *)(buffer - 8);
		printf("Ethernet Frame: \n\t");
		printf("Destination Mac Address : %02x:%02x:%02x:%02x:%02x:%02x\n\t",ethernet_frame1->DA[0],ethernet_frame1->DA[1],ethernet_frame1->DA[2],ethernet_frame1->DA[3],ethernet_frame1->DA[4],ethernet_frame1->DA[5]);
		printf("Source Mac Address : %02x:%02x:%02x:%02x:%02x:%02x\n\n",ethernet_frame1->SA[0],ethernet_frame1->SA[1],ethernet_frame1->SA[2],ethernet_frame1->SA[3],ethernet_frame1->SA[4],ethernet_frame1->SA[5]);
		if(ntohs(ethernet_frame1->type_length) == 0x0800)
		{
			printf("IP datagram : \n\t");
			analyse_IP(ethernet_frame1->buffer);
			printf("\n");
		}
		else if(ntohs(ethernet_frame1->type_length) == 0x0806)
		{
			printf("ARP packet : \n\t");
			analyse_ARP(ethernet_frame1->buffer);
			printf("\n");
		}
		else if(ntohs(ethernet_frame1->type_length) == 0x8035)
		{
			printf("RARP packet : \n\t");
			analyse_RARP(ethernet_frame1->buffer);
			printf("\n");
		}
		else
		{
			printf("add yourself query\n");
		}
	}
	return 0;
}
