#pragma once
#include <cstdio>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <stdio.h>

typedef struct irh
{
    u_int16_t buf;
    u_int16_t it_len;
} IRH;

typedef struct ih
{
    uint8_t subtype;
    uint8_t flags;
    uint16_t duration_id;
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint8_t bss_id[6];
} IH;

typedef struct beacon
{
    uint8_t bss_id[6];
    int beacons;
    char ess_id[256];
    uint8_t ess_id_flag = 0;
} BEACON;

void Usage();
void notice_mac(uint8_t *mac);
void like_airo(int sz);
void dump_pkt(pcap_t *handle);
