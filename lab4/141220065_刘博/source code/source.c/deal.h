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

unsigned short in_cksum(unsigned short *addr, int len) {
	int sum = 0;
	unsigned short res = 0;
	while(len > 1)
	{
		sum += *addr++;
		len -= 2;
	}
	if(len == 1)
	{
		*((unsigned char *)(&res)) = *((unsigned char *)addr);
		sum += res;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	res = ~sum;
	return res;
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
		fscanf(fp,"%s %s %s",p->interface,p->ip_addr,p->mac_addr);
		strcpy(arp_table[arp_item_index].ip_addr,p->ip_addr);
		strcpy(arp_table[arp_item_index].mac_addr,p->mac_addr);
		device_item_index++;
		arp_item_index++;
	}
	device_item_index--;
	//device item index for all device items
	fclose(fp);
}

void make_up_arp(arp_head *arp) {
	if(arp->op == htons(ARP_REQUEST) || arp->op == htons(ARP_REPLY))
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
	for(i = 0; i < route_item_index; i++)
	{
		inet_aton(route_info[i].destination,(struct in_addr *)&addr);
		inet_aton(route_info[i].netmask,(struct in_addr *)&mask);
		if(addr== ((*(unsigned int *)ip->ip_dst) & mask))
		{
#ifdef DEBUG
			printf("find ip hit route table : %d\n",i);
#endif
			return i;
		}
	}
	printf("no hit on ip\n");
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
