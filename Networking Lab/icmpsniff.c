#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>

// Each Ethernet frame starts with an Ethernet header, which contains destination and header


struct ethheader 
{
	u_char ether_dhost [6];
	u_char ether_shost [6];
	u_short ether_type;
};



//IP4 header is header information at the beginning of an Internet Protocol (IP4) packet.

struct ipheader 
{
	unsigned char ip_hl: 4; 
	unsigned char ip_v: 4;
	unsigned short int ip_flag: 3; 
	unsigned short int ip_off: 13;

	struct in_addr source_ip;
	struct in_addr destination_ip;
};



void got_packet(u_char *args, const struct pcap_pkthdr *header,
const u_char *packet)
{


	printf("A Packet has been Captured\n");
	struct ethheader *e = (struct ethheader *)packet;
	if( ntohs(e->ether_type)== 0x0800)
	{
		struct ipheader *ip = (struct ipheader*) (packet + sizeof(struct ethheader));
		printf("  Source: %s\n", inet_ntoa(ip->source_ip));
		printf("  Destination: %s\n",inet_ntoa(ip->destination_ip));

}
}



int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "host 10.9.0.6 or host 10.9.0.1";
bpf_u_int32 net;
handle = pcap_open_live("br-af27d383f404", BUFSIZ, 1, 1000, errbuf);


pcap_compile(handle, &fp, filter_exp, 0, net);
if (pcap_setfilter(handle, &fp) !=0) {
pcap_perror(handle, "Error:");
exit(EXIT_FAILURE);
}


// use to  Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); 
return 0;

}
