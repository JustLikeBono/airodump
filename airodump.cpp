#include "airodump.h"
BEACON arr[100];
int arr_sz = 0;

void Usage()
{
    printf("syntax : ./airodump <interface>\n");
    printf("sample : ./airodump wlan0\n");
}

void notice_mac(uint8_t *mac)
{
    for (int i = 0; i < 5; i++)
        printf("%02X:", mac[i]);

    printf("%02X", mac[5]);
}

void like_airo(int sz)
{
    printf("\033[H\033[J\nBSSID\t\t\tBeacons\t\tESSID\n");

    for (int i = 0; i < sz; i++)
    {
        notice_mac(arr[i].bss_id);
        printf("\t\t%d\t", arr[i].beacons);

        if (arr[i].ess_id_flag)
            printf("%s", arr[i].ess_id);

        puts("");
    }
}

void dump_pkt(pcap_t *handle)
{
    while (1)
    {
        like_airo(arr_sz);

        struct pcap_pkthdr *header;

        const u_char *pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0)
            continue;

        IRH *irh_hdr = (IRH *)pkt;

        IH *ih_hdr = (IH *)(pkt + irh_hdr->it_len);

        int hdr_len = irh_hdr->it_len + sizeof(IH) + 12;

        uint8_t *lan_data = (uint8_t *)(pkt + hdr_len);

        if (ih_hdr->subtype == 0x80)
        {
            int bss_chk = 0;
            for (int i = 0; i < arr_sz; i++)
            {
                if (!memcmp(arr[i].bss_id, ih_hdr->bss_id, 6))
                {
                    bss_chk = 1;

                    arr[i].beacons++;

                    int my_len = header->caplen;

                    int cnt = hdr_len;
                    while (hdr_len < my_len)
                    {
                        int check = pkt[cnt++];
                        int len = pkt[cnt++];
                        if (cnt + len >= my_len)
                            break;

                        if (!check)
                        {
                            arr[i].ess_id_flag = 1;
                            memcpy(arr[i].ess_id, pkt + cnt, len);
                        }
                    }
                }
            }
            if (!bss_chk) 
            {
                BEACON g_beacon;

                memcpy(g_beacon.bss_id, ih_hdr->bss_id, 6);

                g_beacon.beacons = 1;
                int caplen = header->caplen;

                int cnt = hdr_len;
                while (hdr_len < caplen)
                {
                    int check = pkt[cnt++];
                    int len = pkt[cnt++];

                    if (cnt + len >= caplen)
                        break;

                    if (!check)
                    {
                        g_beacon.ess_id_flag = 1;
                        memcpy(g_beacon.ess_id, pkt + cnt, len);
                    }
                }
                memcpy(&arr[arr_sz++], &g_beacon, sizeof(BEACON));
            }
        }
        like_airo(arr_sz);
    }
}
