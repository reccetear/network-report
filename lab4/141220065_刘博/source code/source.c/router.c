#include "router.h"
#include "deal.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <string.h>

int main(int argc, char *argv[]) {
	read_settings();
	
	char src[18] = {0};
	char dst[18] = {0};
	int sock_fd;
	int n_read;
	char buffer[MAX_BUFFER_SIZE];
	eth_head *eth;
	ip_head *ip;
	char *ip_src = (void *)src,*ip_dst = (void *)dst;

	if((sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0)
	{
		printf("error create raw socket\n");
		return -1;
	}

	while(1)
	{
		n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);

		eth = (void *)buffer;


		//hit arp_packet, reflash the arp_buffer
		if(*(unsigned short *)(eth->type) == htons(ETHER_ARP))
		{
			make_up_arp((arp_head *)buffer);
			continue;
		}

		//hit neither arp nor ip
		if(*(unsigned short *)(eth->type) != htons(ETHER_IP))
			continue;

		//hit ip protocal
		ip = (void *)((unsigned char *)eth + sizeof(eth_head));

		sprintf(ip_src,"%d.%d.%d.%d",ip->ip_src[0],ip->ip_src[1],ip->ip_src[2],ip->ip_src[3]);
		sprintf(ip_dst,"%d.%d.%d.%d",ip->ip_dst[0],ip->ip_dst[1],ip->ip_dst[2],ip->ip_dst[3]);
		//printf("ip_src = %s\n",ip_src);
		//printf("ip_dst = %s\n",ip_dst);

		//check whether to be forward
		if(!need_forward(ip->ip_dst,ip->ip_src))
		{
			printf("don't need forward!\n");
			continue;
		}

		//change ttl and checksum
		ip->check_sum = 0;
		int n = (*(unsigned char *)ip)&0x0f;
		ip->live--;
		ip->check_sum = in_cksum((unsigned short*)ip,n*4);

		//read route table and find ip route item index(find next ip)
		int route_temp_index = 0;
		route_temp_index = find_ip(ip);

		char temp_ip[18] = {0};
		char *next_ip = (void *)temp_ip;
		if(*route_info[route_temp_index].gateway != '*')
			strcpy(next_ip,route_info[route_temp_index].gateway);
		else
			strcpy(next_ip,ip_dst);
		//printf("next ip = %s\n",route_info[route_temp_index].gateway);

		if(route_temp_index == -1)
			continue;

		//read device table and find device interface for mac
		int device_temp_index = 0;
		device_temp_index = find_device(route_info[route_temp_index].interface);
		if(device_temp_index == -1)
			return -1;

		//read arp table and find arp item index(find mac for next ip)
		int arp_temp_index = 0;
		arp_temp_index = find_arp(next_ip);
		//printf("first not on arp\n");
		while(arp_temp_index == -1)
		{
			new_arp(device[device_temp_index].mac_addr,device[device_temp_index].ip_addr,next_ip,route_info[route_temp_index].interface);
			arp_temp_index = find_arp(next_ip);
		}

		//change the head of ethernet
		copy_mac(device[device_temp_index].mac_addr,eth->src);
		copy_mac(arp_table[arp_temp_index].mac_addr,eth->dst);

		printf("eth->src = %s\n",device[device_temp_index].mac_addr);
		printf("eth->dst = %s\n",arp_table[arp_temp_index].mac_addr);

		printf("from ip = %s\n",ip_src);
		printf("forward to ip = %s,mac = %s via %s\n",next_ip,device[device_temp_index].mac_addr,device[device_temp_index].interface);

		struct sockaddr_ll addr;
		bzero(&addr,sizeof(addr));
		addr.sll_family = PF_PACKET;
		struct ifreq req;
		strcpy(req.ifr_name, route_info[route_temp_index].interface);
		ioctl(sock_fd,SIOCGIFINDEX,&req);
		addr.sll_ifindex = req.ifr_ifindex;
		
		//send message
		if(sendto(sock_fd,buffer,n_read,0,(struct sockaddr *)(&addr),sizeof(addr)) < 0)
		{
			printf("send error\n");
		}
	}
		return 0;
}
