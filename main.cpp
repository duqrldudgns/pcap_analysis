#include <pcap/pcap.h>
#include <stdio.h>
#include <stdint.h>

struct ethernet_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

struct ip_header{
    uint8_t verandhl;
    uint8_t tos;
    uint16_t totallen;
    uint16_t id;
    uint16_t flagsandoff;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t sip[4];
    uint8_t dip[4];
};

struct tcp_header{
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint16_t flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentpointer;
};

void printpacket(const uint8_t* packet){
    struct ethernet_header *eh;
    eh = (struct ethernet_header *) packet;
    struct ip_header *iph;
    iph = (struct ip_header *) (packet+14);
    struct tcp_header *tcph;
    tcph = (struct tcp_header *) (packet+34);
    int i;
    uint8_t http_data[16];
    eh->type=(*(packet+12)<<8)+(*(packet+13));
    iph->protocol=*(packet+23);
    tcph->sport=(*(packet+34)<<8)+*(packet+35);
    tcph->dport=(*(packet+36)<<8)+*(packet+37);

    if( eh->type==0x0800 && iph->protocol==0x06 && tcph->dport==0x0050)
    {
        printf("HTTP CATCH\n");
        printf("Smac : ");
        for(i = 0; i<=5 ;i++){
            printf("%02x", eh->smac[i]);
            if(i<=4) printf(":");
	    else printf("\n");
	}
        printf("Dmac : ");
        for(i = 0; i<=5 ;i++){
            printf("%02x", eh->dmac[i]);
            if(i<=4) printf(":");
	    else printf("\n");
	}
        printf("SIP : ");
        for(i=0;i<=3;i++){
	    printf("%d",iph->sip[i]);
            if(i<3) printf(".");
            else printf("\n");
        }
        printf("DIP : ");
        for(i=0;i<=3;i++){
	    printf("%d",iph->dip[i]);
            if(i<3) printf(".");
            else printf("\n");
        }
        printf("SPort : %d\n",tcph->sport);
	printf("DPort : %d\n",tcph->dport);

	printf("HTTP : ");        
	for(i=0;i<16;i++){
            http_data[i]=*(packet+54+i);
            printf("%c",http_data[i]);
        }        
        printf("\n\n");
    }
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printpacket(packet);
  }

  pcap_close(handle);
  return 0;
}

