#ifndef __DEAL_H__
#define __DEAL_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include "router.h"

#define true 1
#define false 0
#define bool unsigned char

int arp_local(unsigned char *arp_temp);
void add_arp(unsigned char *new_ip, unsigned char *new_mac);

unsigned short in_cksum(unsigned short* buff, int size)
{
    unsigned long cksum = 0;
    while(size>1)
    {
        cksum += *buff++;
        size -= 2;
    }
    if(size)
    {
        cksum += *(unsigned char*)buff;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);            
    return (unsigned short)(~cksum);
}

void read_settings(void) {
	FILE *fp = fopen("../configuration.file/route_table.txt","r");
	while(!feof(fp))
	{
		route_item *p = (route_item *)route_info + route_item_index;
		fscanf(fp,"%s %s %s %s",p->destination,p->gateway,p->netmask,p->interface);
		route_item_index++;
	}
	route_item_index--;
	//route item index for all route items
	fclose(fp);
	fp = fopen("../configuration.file/device_table.txt","r");
	while(!feof(fp))
	{
		device_item *p = (device_item *)device + device_item_index;
		fscanf(fp,"%s %s %s %d",p->interface,p->ip_addr,p->mac_addr,&p->is_entrance);
		strcpy(arp_table[arp_item_index].ip_addr,p->ip_addr);
		strcpy(arp_table[arp_item_index].mac_addr,p->mac_addr);
		device_item_index++;
		arp_item_index++;
	}
	device_item_index--;
	//device item index for all device items
	fclose(fp);
	fp = fopen("../configuration.file/VPN_route.txt","r");
	while(!feof(fp))
	{
		VPN_item *p = (VPN_item *)VPN_route_info + VPN_item_index;
		fscanf(fp,"%s %s %s",p->dst,p->VPN_dst,p->netmask);
		VPN_item_index++;
	}
	VPN_item_index--;
	fclose(fp);
}

void make_up_arp(arp_head *arp) {
	if(arp->op == htons(ARP_REPLY) || arp->op == htons(ARP_REQUEST))
	{
		char *ip_temp = inet_ntoa(*(struct in_addr *)&arp->ip_sender);
		unsigned char mac_temp[18] = {0};
		unsigned char *mac = arp->mac_sender;
		sprintf(mac_temp,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
		if(arp_local(ip_temp) == -1)
			add_arp(ip_temp,mac_temp);
	}
}

int arp_local(unsigned char *arp_temp) {
	int i;
	for(i = 0; i < arp_item_index; i++)
	{
		if(strcmp(arp_table[i].ip_addr,arp_temp) == 0)
			return i;
	}
	return -1;
}

void add_arp(unsigned char *new_ip, unsigned char *new_mac) {
	if(arp_item_index < MAX_ARP_SIZE)
	{
		strcpy(arp_table[arp_item_index].ip_addr,new_ip);
		strcpy(arp_table[arp_item_index].mac_addr,new_mac);
		arp_item_index++;
	}
	else
	{
		printf("no enough space to restore arp");
	}
	return;
}

bool need_forward(unsigned char *src, unsigned char *dst) {
	int i;
	for(i = 0; i < device_item_index; i++)
	{
		unsigned int addr;
		inet_aton(device[i].ip_addr,(struct in_addr *)&addr);
		//if the dst or the src ip belongs to router,no need to forward
		if(*(unsigned int *)src == addr || *(unsigned int *)dst == addr)
		return false;
	}
	return true;
}

int find_ip(ip_head *ip) {
	unsigned int addr;
	unsigned int mask;
	int i;
	int Default = -1;

	for(i = 0; i < route_item_index; i++)
	{
		if(strcmp(route_info[i].destination,"default") == 0)
		{
			if(Default == -1)
			{
				Default = i;
				continue;
			}
			else
			{
				printf("should not have two default destinations\n");
				return -1;
			}
		}
		inet_aton(route_info[i].destination,(struct in_addr *)&addr);
		inet_aton(route_info[i].netmask,(struct in_addr *)&mask);
		if(addr == ((*(unsigned int *)ip->ip_dst) & mask))
		{
#ifdef DEBUG
			printf("find ip hit route table : %d\n",i);
#endif
			return i;
		}
	}
	printf("hit default = %d\n",Default);
	return Default;
}

int find_VPN_ip(ip_head *ip) {
	int i;
	unsigned int dst_addr;
	unsigned int mask;
	for(i = 0; i <  VPN_item_index; i++)
	{
		inet_aton(VPN_route_info[i].dst,(struct in_addr *)&dst_addr);
		inet_aton(VPN_route_info[i].netmask,(struct in_addr *)&mask);
		if(((*(unsigned int *)ip->ip_dst) & mask) == dst_addr)
		{
			printf("hit VPN route\n");
			return i;
		}
	}
	printf("not hit on VPN route\n");
	return -1;
}

int detect_packet(ip_head *ip) {
	unsigned char local_net[16];
	unsigned char local_gw[16];
	unsigned char over_net[16];
	unsigned char over_gw[16];
	int i;
	for(i = 0; i < device_item_index; i++)
	{
		if(device[i].is_entrance)
			strcpy(local_net,device[i].ip_addr);
		else
			strcpy(local_gw,device[i].ip_addr);
	}
	for(i = 0; i < VPN_item_index; i++)
	{
		strcpy(over_net,VPN_route_info[i].dst);
		strcpy(over_gw,VPN_route_info[i].VPN_dst);
		unsigned int dst_addr;
		unsigned int src_addr;
		unsigned int mask;
		inet_aton(local_net,(struct in_addr *)&src_addr);
		inet_aton(over_net,(struct in_addr *)&dst_addr);
		inet_aton(VPN_route_info[i].netmask,(struct in_addr *)&mask);
		if((((*(unsigned int *)ip->ip_src) & mask) == (src_addr & mask)) && (((*(unsigned int *)ip->ip_dst) & mask) == (dst_addr & mask)))
			return PACK;
		inet_aton(local_gw,(struct in_addr *)&dst_addr);
		inet_aton(over_gw,(struct in_addr *)&src_addr);
		if((((*(unsigned int *)ip->ip_src) & mask) == (src_addr & mask)) && (((*(unsigned int *)ip->ip_dst) & mask) == (dst_addr & mask)))
			return UNPACK;
	}
	return -1;
}
	
	

int find_arp(char *next_ip) {
	int i;
	for(i = 0; i < arp_item_index; i++)
	{
		if(strcmp(next_ip,arp_table[i].ip_addr) == 0)
		{
#ifdef DEBUG
			printf("find mac hit arp table : %d\n",i);
#endif
			return i;
		}
	}
	printf("no hit on mac\n");
	return -1;
}

int find_device(unsigned char *interface) {
	int i;
	for(i = 0; i < device_item_index; i++)
	{
		if(strcmp(interface, device[i].interface) == 0)
		{
#ifdef DEBUG
			printf("hit device on device : %s\n",device[i].interface);
#endif
			return i;
		}
	}
	printf("no hit on device\n");
	return -1;
}

void copy_mac(unsigned char *p,unsigned char *q) {
	unsigned int t[6];
	sscanf(p, "%x:%x:%x:%x:%x:%x",t,t+1,t+2,t+3,t+4,t+5);
	int i;
	for(i = 0; i < 6; i++)
		*q++ = t[i];
}

void copy_ip(unsigned char *p,unsigned char *q) {
	unsigned int t[4];
	sscanf(p, "%d.%d.%d.%d",t,t+1,t+2,t+3);
	int i;
	for(i = 0; i < 4; i++)
		*q++ = t[i];
}

void new_arp(unsigned char *mac_addr,unsigned char *src_ip,unsigned char *dst_ip,unsigned char *interface) {
	int sock_fd;
	arp_head arp;
	struct in_addr sender,receiver;
	struct sockaddr_ll sl;

	if((sock_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ARP))) < 0)
	{
		printf("error create arp packet!\n");
		return;
	}
	
	//fill arp packet
	memset(&arp,0, sizeof(arp_head));

	//ether addr
	copy_mac("ff:ff:ff:ff:ff:ff",arp.mac_target);
	copy_mac(mac_addr,arp.mac_source);

	arp.ethertype = htons(ETHER_ARP);
	arp.hw_type = htons(0x1);;
	arp.proto_type = htons(ETHER_IP);
	arp.mac_addr_len = 6;
	arp.ip_addr_len = 4;
	arp.op = htons(ARP_REQUEST);
	//arp addr
	copy_mac(mac_addr,arp.mac_sender);
	inet_aton(src_ip,&sender);
	memcpy(&arp.ip_sender,&sender,sizeof(sender));
	inet_aton(dst_ip,&receiver);
	memcpy(&arp.ip_receiver,&receiver,sizeof(receiver));

	//create struct sockaddr for sendto
	struct sockaddr_ll addr;
	memset(&addr,0,sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);
	struct ifreq req;
	strcpy(req.ifr_name,interface);
	int s;
	if((s = socket(AF_PACKET,SOCK_DGRAM,0)) < 0)
		printf("socket AF_INET error\n");
	ioctl(s,SIOCGIFINDEX,&req);
	close(s);
	memset(&sl,0,sizeof(sl));
	sl.sll_family = AF_PACKET;
	sl.sll_ifindex = req.ifr_ifindex;
	
	//send
	int len = sendto(sock_fd, &arp, sizeof(arp), 0, (struct sockaddr *)&sl, sizeof(sl));
	int n_read;
	unsigned char buffer[100];

	//receive
	n_read = recvfrom(sock_fd, buffer, 2048, 0, NULL, NULL);
	make_up_arp((arp_head *)buffer);
}
#endif
