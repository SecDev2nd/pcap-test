#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "pcap_struct.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


void print_mac(u_int8_t *m){
	printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_ip(struct libnet_ipv4_hdr *header)
{
	printf("IP : %s -> ",inet_ntoa(header->ip_src));
	printf("%s\n",inet_ntoa(header->ip_dst));
}

void print_ip2(struct libnet_ipv4_hdr *header) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    printf("IP : %s\n", src_ip);
    printf("%s\n", dst_ip);
}

bool check_tcp(u_int8_t type){
	if(type != 6){
		return false;
	}
	return true;
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

//paring argument
bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv)){
		return -1;
	}
		

	char errbuf[PCAP_ERRBUF_SIZE];
	
	//open pcap for captured packet
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}


	// pacp capturing....
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// Ethernet Header의 src mac / dst mac
		// IP Header의 src ip / dst ip
		// TCP Header의 src port / dst port
		// Payload(Data)의 hexadecimal value(최대 10바이트까지만)
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet+sizeof(*eth_hdr));
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet+sizeof(*ip_hdr)+sizeof(*eth_hdr));




		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
