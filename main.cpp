#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#define TCP 0x06
#define IPv4 0x08

typedef unsigned char BYTE;
struct ip *iph;
struct tcphdr *tcph;
struct ethhdr *ehdr;

int printMACaddr(const u_char* packet);
int printIPaddr(const u_char* packet);
int printTCPport(const u_char* packet);

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

  while (true){
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    int i;
    int ismac;	
    int iphdl;
    int tphdl;
    int datalen;
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    ismac = printMACaddr(packet);
    if(ismac == 1) {
    	packet = packet + 14;
    	iphdl = printIPaddr(packet);
	datalen = iph->ip_len;
	datalen = ntohs(datalen);
	datalen -= iphdl*4;
	if(iphdl != 0) {
		packet += iphdl*4;
		tphdl = printTCPport(packet);
		datalen -= tphdl*4;
		if(datalen > 0) {
			packet += tphdl*4;
			printf("DATA ");
			if(datalen < 16) {
				for(i=0; i<datalen-1; i++)
				printf("%02x ", packet[i]);
			}
			else {
				for(i=0; i<15; i++)
				printf("%02x ", packet[i]);
			}
		}
	}
    }
    printf("%u bytes captured\n", header->caplen);
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}

int printMACaddr(const u_char* packet) {
	ehdr = (struct ethhdr *)packet;
	int i;
	printf("MAC SRC Addr ");
	for(i=0; i<5; i++)
		printf("%02x:", ehdr->h_source[i]);
	printf("%02x\n", ehdr->h_source[5]);

	printf("MAC DST Addr ");
	for(i=0; i<5; i++)
		printf("%02x:", ehdr->h_dest[i]);
	printf("%02x\n", ehdr->h_dest[5]);


	if(ntohs(ehdr->h_proto)==0x0800) 
		return 1;
	return 0;
}

int printIPaddr(const u_char* packet) {
	iph = (struct ip *)packet;
	printf("IP SRC addr %s \n", inet_ntoa(iph->ip_src));
	printf("IP DST addr %s \n", inet_ntoa(iph->ip_dst));

	if(iph->ip_p == IPPROTO_TCP)
		return iph->ip_hl;
	return 0;
}

int printTCPport(const u_char* packet) {
	tcph = (struct tcphdr *)packet;
	printf("TCP SRC port %d \n", ntohs(tcph->th_sport));
	printf("TCP DST port %d \n", ntohs(tcph->th_dport));
	return tcph->th_off;
}
