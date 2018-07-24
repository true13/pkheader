#include <pcap.h>
#include <stdio.h>

#define TCP 0x06

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
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    int i;
	
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if(packet[12] == 0x08 && packet[13] == 0x00 && packet[0x17] == TCP) {
    	printf("MAC dst addr ");
    	for(i=0; i<5; i++)
    	printf("%02x:", packet[i]);
    	printf("%02x", packet[5]);
    	printf("\n");
    	printf("MAC src addr ");
    	for(i=6; i<11; i++)
    	printf("%02x:", packet[i]);
    	printf("%02x", packet[11]);
    	printf("\n");

	printf("IP src addr ");
	for(i=0x1A; i<0x1D; i++)
	printf("%d.", packet[i]);
	printf("%d\n", packet[0x1D]);
	printf("IP dst addr ");
	for(i=0x1E; i<0x21; i++)
	printf("%d.", packet[i]);
	printf("%d\n", packet[0x21]);

	printf("Port src ");
	printf("%d\n", packet[0x22]*0x100 + packet[0x23]);
	printf("Port dst ");
	printf("%d\n", packet[0x24]*0x100 + packet[0x25]);
	int datalen = (int)header->caplen - (int)((packet[0x0e]%16)*4) - (int)(packet[0x2e]/16*4);
	if(datalen >= 46) {
	    printf("Data ");
	    for(i=1; i<=4; i++)
                printf("%02x ", packet[0x21+(packet[0x2e]/16)*4+i]);
	    printf("\n");
	}
    }
    printf("%u bytes captured\n", header->caplen);
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
