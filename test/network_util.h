#ifndef NETWORK_UTIL_H
#define NETWORK_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

uint16 internet_checksum(uint8* data, size_t len);

uint16 crc_checksum(uint8* data, size_t len);

struct iphdr* ip_deserial(uint8* data, size_t len);

uint8* ip_serial(struct iphdr* ip);

struct tcphdr* tcp_deserial(uint8* data, size_t len);

uint8* tcp_serial(struct tcphdr* tcp);

#endif

