#include "airodump.h"


int main(int argc, char **argv)
{
    if (argc != 2)
    {
        Usage();
        return 0;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);

    dump_pkt(handle);

    pcap_close(handle);

    return 0;
}

