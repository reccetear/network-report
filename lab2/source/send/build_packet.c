#include "socket_head.h"

unsigned short checksum(unsigned short* buff, int size)
{
    unsigned long cksum = 0;
    while(size>1)
    {
        cksum += *buff++;
        size -= sizeof(unsigned short);
    }
    if(size)
    {
        cksum += *(unsigned char*)buff;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);            
    return (unsigned short)(~cksum);
}
