#include <string.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "network_util.h"

static uint8 data1[] = {0x45, 0x00, 0x00, 0x8c, 0x28, 0xd1, 0x00, 0x00, 0xff, 0x06, 0x00, 0x00, 0x73, 0xef, 0xd2, 0x1b,
0xac, 0x15, 0x00, 0x01, 0x00, 0x50, 0xe7, 0xa3, 0x93, 0x2d, 0xac, 0xdb, 0x9d, 0x0e, 0x0f, 0x41,
0x50, 0x10, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x34, 0x70, 0x78, 0x3b, 0x70, 0x61, 0x64, 0x64,
0x69, 0x6e, 0x67, 0x2d, 0x6c, 0x65, 0x66, 0x74, 0x3a, 0x31, 0x30, 0x70, 0x78, 0x3b, 0x70, 0x61,
0x64, 0x64, 0x69, 0x6e, 0x67, 0x2d, 0x72, 0x69, 0x67, 0x68, 0x74, 0x3a, 0x31, 0x30, 0x70, 0x78,
0x3b, 0x63, 0x75, 0x72, 0x73, 0x6f, 0x72, 0x3a, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x3b,
0x6f, 0x76, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x77, 0x3a, 0x68, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x3b,
0x77, 0x68, 0x69, 0x74, 0x65, 0x2d, 0x73, 0x70, 0x61, 0x63, 0x65, 0x3a, 0x6e, 0x6f, 0x77, 0x72,
0x61, 0x70, 0x7d, 0x2e, 0x63, 0x2d, 0x64, 0x72, 0x6f, 0x70, 0x64, 0x6f};

uint8* task1(uint8* data, size_t len)
{
    if (NULL == data || 0 == len)
    {
        return NULL;
    }
    
    uint8* retData = NULL;
    size_t ip_len = sizeof(struct iphdr);
    size_t tcp_len = sizeof(struct tcphdr);

    //For IPv4
    struct iphdr* ip = ip_deserial(data, ip_len);
    if (ip != NULL && ip->version ==4 && ip->ihl == 5)
    {
        uint16 ipCheckSum = internet_checksum(data, ip_len);
        ip->check = htons(ipCheckSum);
    }

    uint8* ipData = ip_serial(ip);

    //For TCP but not fragment
    struct tcphdr* tcp = tcp_deserial(data + ip_len, tcp_len);
    if (tcp != NULL)
    {
        uint16 tcpCheckSum = tcp_checksum(ip->saddr,
                                          ip->daddr,
                                          (uint16)(ip->protocol),
                                          ntohs(ip->tot_len) - ip_len,
                                          data + ip_len);
        printf("TCP check sum[0x%02x]\n", tcpCheckSum);
        tcp->check = htons(tcpCheckSum);
    }

    uint8* tcpData = tcp_serial(tcp);

    if (ipData != NULL && tcpData != NULL)
    {
        retData = (uint8*)malloc(len);
        memcpy(retData, ipData, ip_len);
        memcpy(retData + ip_len, tcpData, tcp_len);
        memcpy(retData + ip_len + tcp_len, data + ip_len + tcp_len, len - (ip_len + tcp_len));
    }

    if (ipData != NULL)
    {
        free(ipData);
    }

    if (tcpData != NULL)
    {
        free(tcpData);
    }

    return retData;
}

void task2()
{
    int sock, n;
    char buffer[2048];
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sockaddr_ll sll;
    struct ifreq ifstruct;

    memset(&sll, 0, sizeof(struct sockaddr_ll));
    //strcpy(ifstruct.ifr_name, "p3p1");
    strcpy(ifstruct.ifr_name, "lo");

    if (0 > (sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))))
    {
        perror("socket\n");
        exit(1);
    }

    if (ioctl(sock, SIOCGIFINDEX, &ifstruct) == -1)
    {
        printf("ioctl SIOCGIFINDEX Error!!!\n");
        close(sock);
        exit(1);
    }

    sll.sll_family   = PF_PACKET;
    sll.sll_ifindex  = ifstruct.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_hatype   = ARPHRD_ETHER;
    sll.sll_pkttype  = PACKET_OTHERHOST;
    sll.sll_halen    = ETH_ALEN;
    sll.sll_addr[6]  = 0;
    sll.sll_addr[7]  = 0;

    if (ioctl(sock, SIOCGIFHWADDR, &ifstruct) == -1)
    {
        printf("ioctl SIOCGIFHWADDR Error!!!\n");
        close(sock);
        exit(1);
    }

    if (ioctl(sock, SIOCGIFFLAGS, &ifstruct) < 0)
    {
        printf("ioctl SIOCGIFFLAGS Error!!!\n");
        close(sock);
        exit(1);
    }
#if 1
    ifstruct.ifr_flags |= IFF_PROMISC;   //set promisc
    if (ioctl(sock, SIOCSIFFLAGS, &ifstruct) == -1)
    {
        printf("Set promisc error\n");
        close(sock);
        exit(1);
    }
#endif
    if (bind(sock, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) == -1)
    {
        printf("Bind Error!\n");
        close(sock);
        exit(1);
    }

    while (1)
    {
        printf("=====================================\n");
        n = read(sock,buffer,2048);
        printf("%d bytes read\n",n);

        eth = (struct ethhdr*)buffer;
        printf("Dest MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
        printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);

        iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        if (iph->version ==4 && iph->ihl == 5)
        {
            struct in_addr saddr;
            saddr.s_addr = iph->saddr;
            struct in_addr daddr;
            daddr.s_addr = iph->daddr;
            printf("Source host:%s\n", inet_ntoa(saddr));
            printf("Dest host:%s\n", inet_ntoa(daddr));
        }

        tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct tcphdr));
        if (tcph != NULL)
        {
            printf("Source address:%d\n", ntohs(tcph->source));
            printf("Dest address:%d\n", ntohs(tcph->dest));
            printf("Seq:%x\n", ntohs(tcph->seq));
            printf("Ack seq:%x\n", ntohs(tcph->ack_seq));
            printf("Check:%x\n", ntohs(tcph->check));
        }
    }
}

int main(int argc, char* argv[])
{
    uint8* newData = task1(data1, sizeof(data1));
    if (newData != NULL)
    {
        int index = 0;
        printf("Input:\n");
        printf("[");
        while (index < sizeof(data1))
        {
            printf("0x%02x, ", data1[index++]);
        }
        printf("]\n");

        index = 0;
        printf("Output:\n");
        printf("[");
        while (index < sizeof(data1))
        {
            printf("0x%02x, ", newData[index++]);
        }
        printf("]\n");
    }

    task2();

    return 0;
}

