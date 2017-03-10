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
#include <memory.h>

int main(int argc, char *argv[]) {
	read_settings();
	
	char src[18] = {0};
	char dst[18] = {0};
	int sock_fd;
	int n_read;
	char buffer[MAX_BUFFER_SIZE];
	char VPN_packet[MAX_BUFFER_SIZE];
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

		int operation = detect_packet(ip);

		if(operation == PACK)
		{
			printf("PACK\n");
			int VPN_temp_index = 0;
			VPN_temp_index = find_VPN_ip(ip);
			if(VPN_temp_index == -1)
			{
				printf("not in VPN route table\n");
			}
			else
			{
				//pack a new VPN packet
				eth_head *VPN_eth = (void *)VPN_packet;
				//copy_eth_ip_icmp
				memcpy((void *)VPN_eth,(void *)eth,sizeof(eth_head) + sizeof(ip_head) + 16);
				//change ip_dst
				ip_head *VPN_ip = (void *)((unsigned char *)VPN_eth + sizeof(eth_head));
				copy_ip(VPN_route_info[VPN_temp_index].VPN_dst,VPN_ip->ip_dst);
				int temp;
				for(temp = 0; temp < device_item_index; temp++)
				{
					if(!device[temp].is_entrance)
						copy_ip(device[temp].ip_addr,VPN_ip->ip_src);
				}
				//change ip_length
				unsigned short len = ntohs(ip->length) + sizeof(ip_head) + 16;
				VPN_ip->length = htons(len);
				//copy data
				char *cat = (char *)VPN_ip + sizeof(ip_head) + 16;
				memcpy(cat,buffer + sizeof(eth_head),2048 - (sizeof(eth_head) + sizeof(ip_head) + 16));
				eth = VPN_eth;
				ip = VPN_ip;
				n_read = n_read + sizeof(ip_head) + 16;
			}
		}
		else if(operation == UNPACK)
		{
			printf("UNPACK\n");
			//unpack a VPN packet
			eth_head *VPN_eth = (void *)VPN_packet;
			//copy_eth_ip_icmp
			memcpy((void *)VPN_eth,(void *)eth,sizeof(eth_head) + sizeof(ip_head) + 16);
			//change ip_dst
			ip_head *VPN_ip = (void *)((unsigned char *)VPN_eth + sizeof(eth_head));
			ip_head *pre_ip = (void *)((unsigned char *)eth + sizeof(eth_head) + sizeof(ip_head) + 16);
			memcpy(VPN_ip->ip_dst,pre_ip->ip_dst,4);
			memcpy(VPN_ip->ip_src,pre_ip->ip_src,4);
			//change ip_length
			unsigned short len = ntohs(pre_ip->length);
			VPN_ip->length = htons(len);
			//copy data
			char *cat = (char *)VPN_ip + sizeof(ip_head) + 16;
			memcpy(cat,buffer + sizeof(eth_head) + (sizeof(ip_head) + 16) * 2,2048 - (sizeof(eth_head) + (sizeof(ip_head) + 16) * 2));
			eth = VPN_eth;
			ip = VPN_ip;
			n_read = len + sizeof(eth_head);
		}
		else
		{
			//check whether to be forward
			if(!need_forward(ip->ip_dst,ip->ip_src))
			{
				printf("don't need forward!\n");
				continue;
			}
		}

		sprintf(ip_src,"%d.%d.%d.%d",ip->ip_src[0],ip->ip_src[1],ip->ip_src[2],ip->ip_src[3]);
		sprintf(ip_dst,"%d.%d.%d.%d",ip->ip_dst[0],ip->ip_dst[1],ip->ip_dst[2],ip->ip_dst[3]);
		printf("ip_src = %s\n",ip_src);
		printf("ip_dst = %s\n",ip_dst);

		//change ip_ttl and ip_checksum
		ip->check_sum = 0;
		int n = (*(unsigned char *)ip)&0x0f;
		ip->live--;
		ip->check_sum = in_cksum((unsigned short*)ip,20);

		icmp_head *icmp = (void *)((unsigned char *)ip + sizeof(ip_head));
		//change icmp_check_sum
		icmp->check_sum = 0;
		icmp->check_sum = in_cksum((unsigned short*)icmp,ntohs(ip->length) - 20);

		//read route table and find ip route item index(find next ip)
		int route_temp_index = 0;
		route_temp_index = find_ip(ip);

		char temp_ip[18] = {0};
		char *next_ip = (void *)temp_ip;
		if(*route_info[route_temp_index].gateway != '*')
			strcpy(next_ip,route_info[route_temp_index].gateway);
		else
			strcpy(next_ip,ip_dst);

		if(route_temp_index == -1)
		{
			printf("should flash route table\n");
			return -1;
		}

		//read device table and find device interface for mac
		int device_temp_index = 0;
		device_temp_index = find_device(route_info[route_temp_index].interface);
		if(device_temp_index == -1)
		{
			printf("should falsh device table\n");
			return -1;
		}

		//read arp table and find arp item index(find mac for next ip)
		int arp_temp_index = 0;
		arp_temp_index = find_arp(next_ip);
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
		if(sendto(sock_fd,VPN_packet,n_read,0,(struct sockaddr *)(&addr),sizeof(addr)) < 0)
		{
			printf("send error\n");
		}
	}
		return 0;
}
