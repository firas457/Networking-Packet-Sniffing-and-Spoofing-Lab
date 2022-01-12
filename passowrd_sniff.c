#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>


struct ethheader 
{
	u_char ether_dhost [6];
	u_char ether_shost [6];
	u_short ether_type;
};





struct ipheader 
{
	unsigned char ip_hl: 4; 
	unsigned char ip_v: 4;
	unsigned short int ip_flag: 3; 
	unsigned short int ip_off: 13; 
	struct in_addr source_ip;
	struct in_addr destination_ip;
	 unsigned char ip_protocol;
};





void got_packet(u_char *args, const struct pcap_pkthdr *header,
const u_char *packet)
{
	int i=0;
	printf("A Packet has been Captured\n");
	struct ethheader *e = (struct ethheader *)packet;
	if( ntohs(e->ether_type)== 0x0800)
	{
		struct ipheader *ip = (struct ipheader*) (packet + sizeof(struct ethheader));
		if( ip->ip_protocol == IPPROTO_TCP)
{



			for(i=0; i < header->caplen; ++i)
{



				if(65<=packet[i] && packet[i]<=90 && 97<=packet[i]&& packet[i]<= 122)
{
					putchar(packet[i]);
					printf("%c",packet[i]);
}
					else
{
					putchar('.');
}

}
					printf("\n");
}


}
}



int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "tcp and port 23";
bpf_u_int32 net;
handle = pcap_open_live("br-96f6fc290721", BUFSIZ, 1, 1000, errbuf);


pcap_compile(handle, &fp, filter_exp, 0, net);
if (pcap_setfilter(handle, &fp) !=0) {
pcap_perror(handle, "Error:");
exit(EXIT_FAILURE);
}




pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); 


return 0;
}
