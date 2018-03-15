#include "network_util.h"

uint16 internet_checksum(uint8* data, size_t len)
{
    if (NULL == data || 0 == len)
    {
        return 0;
    }

    uint32 retCheckSum = 0;
    while (len > 1)
    {
        retCheckSum += ((uint16)(*data) << 8) + (*(data + 1));
        data += sizeof(uint16);
        len -= sizeof(uint16);
    }

    //Correspond for odd number
    if (len == 1)
    {
        retCheckSum += (uint16)(*data) << 8;
    }

    while (retCheckSum >> 16)
    {
        retCheckSum = (retCheckSum & 0xffff) + (retCheckSum >> 16);
    }

    return (uint16)(~retCheckSum);
}

struct iphdr* ip_deserial(uint8* data, size_t len)
{
    if (NULL == data || len != sizeof(struct iphdr))
    {
        return NULL;
    }

    struct iphdr* retIpHdr = (struct iphdr*)malloc(sizeof(struct iphdr));

    //ihl and version but not care litte or big endian
    *(uint8*)retIpHdr = *data;
    data += sizeof(uint8);

    //TOS
    retIpHdr->tos = *data;
    data += sizeof(uint8);

    //Total length
    retIpHdr->tot_len = *(uint16*)data;
    data += sizeof(uint16);
    
    //Id
    retIpHdr->id = *(uint16*)data;
    data += sizeof(uint16);

    //Fragment offset
    retIpHdr->frag_off = *(uint16*)data;
    data += sizeof(uint16);

    //TTL
    retIpHdr->ttl = *data;
    data += sizeof(uint8);

    //Protocol
    retIpHdr->protocol = *data;
    data += sizeof(uint8);

    //Check sum
    retIpHdr->check = *(uint16*)data;
    data += sizeof(uint16);

    //Source address
    retIpHdr->saddr = *(uint32*)data;
    data += sizeof(uint32);

    //Destination address
    retIpHdr->daddr = *(uint32*)data;
    data += sizeof(uint32);

    return retIpHdr;
}

uint8* ip_serial(struct iphdr* ip)
{
    if (NULL == ip)
    {
        return NULL;
    }

    uint8* retData = (uint8*)malloc(sizeof(struct iphdr));
    uint8* data = retData;

    *(uint8*)data = *(uint8*)ip;
    data += sizeof(uint8);

    *(uint8*)data = ip->tos;
    data += sizeof(uint8);

    *(uint16*)data = ip->tot_len;
    data += sizeof(uint16);

    *(uint16*)data = ip->id;
    data += sizeof(uint16);

    *(uint16*)data = ip->frag_off;
    data += sizeof(uint16);

    *(uint8*)data = ip->ttl;
    data += sizeof(uint8);

    *(uint8*)data = ip->protocol;
    data += sizeof(uint8);

    *(uint16*)data = ip->check;
    data += sizeof(uint16);

    *(uint32*)data = ip->saddr;
    data += sizeof(uint32);

    *(uint32*)data = ip->daddr;
    data += sizeof(uint32);

    return retData;
}

struct tcphdr* tcp_deserial(uint8* data, size_t len)
{
    if (NULL == data || len != sizeof(struct tcphdr))
    {
        return NULL;
    }

    struct tcphdr* retTcpHdr = (struct tcphdr*)malloc(sizeof(struct tcphdr));

    //Source port
    retTcpHdr->source = *(uint16*)data;
    data += sizeof(uint16);

    //Destination port
    retTcpHdr->dest = *(uint16*)data;
    data += sizeof(uint16);

    //Sequence number
    retTcpHdr->seq = *(uint32*)data;
    data += sizeof(uint32);

    //ACK sequence number
    retTcpHdr->ack_seq = *(uint32*)data;
    data += sizeof(uint32);

    //|doff|res1|URG|ACK|PSH|RST|SYN|FIN|
    *((uint16*)(retTcpHdr) + 6) = *(uint16*)data;
    data += sizeof(uint16);

    //Window size
    retTcpHdr->window = *(uint16*)data;
    data += sizeof(uint16);

    //Check sum
    retTcpHdr->check = *(uint16*)data;
    data += sizeof(uint16);

    //URG ptr
    retTcpHdr->urg_ptr = *(uint16*)data;
    data += sizeof(uint16);

    return retTcpHdr;
}

uint8* tcp_serial(struct tcphdr* tcp)
{
    if (NULL == tcp)
    {
        return NULL;
    }

    uint8* retData = (uint8*)malloc(sizeof(struct tcphdr));
    uint8* data = retData;

    *(uint16*)data = tcp->source;
    data += sizeof(uint16);

    *(uint16*)data = tcp->dest;
    data += sizeof(uint16);

    *(uint32*)data = tcp->seq;
    data += sizeof(uint32);

    *(uint32*)data = tcp->ack_seq;
    data += sizeof(uint32);

    *(uint16*)data = *((uint16*)(tcp) + 6);
    data += sizeof(uint16);

    *(uint16*)data = tcp->window;
    data += sizeof(uint16);

    *(uint16*)data = tcp->check;
    data += sizeof(uint16);

    *(uint16*)data = tcp->urg_ptr;
    data += sizeof(uint16);

    return retData;
}

