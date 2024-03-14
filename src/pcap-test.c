#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "pcap_struct.h"


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}
void print_mac(struct libnet_ethernet_hdr *eth_hdr) {
    u_int8_t *src = eth_hdr->ether_shost;
    u_int8_t *dst = eth_hdr->ether_dhost;
    
    printf("MAC \t: %02x:%02x:%02x:%02x:%02x:%02x \t---> %02x:%02x:%02x:%02x:%02x:%02x\n",
           src[0], src[1], src[2], src[3], src[4], src[5],
           dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
}

void print_tcp_port(struct libnet_tcp_hdr *tcp_header) {
    printf("PORT \t: %u     \t\t---> %u\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
}

void print_inet_ntop(struct libnet_ipv4_hdr *header) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    printf("IP \t: %s \t---> %s \t\n", src_ip, dst_ip);
}


bool check_tcp(u_int8_t type) {
    return type == 6;
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
		// TCP packet이 잡히는 경우 "ETH + IP + TCP + DATA" 로 구성이 된다
		// 그렇다면 전체 패킷에서 ETH+IP+TCP만큼 뺴주면 DATA가 나오지 않을까
		// ETH헤더 : ETH프레임에서의 MAC헤더가 14바이트
		// IP헤더랑 tcp헤더 오프셋은 32bit(4byte)단위로 나타내기 때문에 *4
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet+sizeof(*eth_hdr));
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet+sizeof(*ip_hdr)+sizeof(*eth_hdr));
		

		if (check_tcp(ip_hdr->ip_p)) { //*ip_p -> protocol */
			u_int32_t total_length = header->caplen; //캡쳐된 패킷 길이(실제 길이랑은 다름)
			u_int32_t header_length = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4; //헤더의 총 길이
			u_int32_t payload_length = total_length - header_length;
			
			printf("%u bytes captured\n", total_length);
			printf("Protocol : TCP\n");
			print_mac(eth_hdr);
			print_tcp_port(tcp_hdr);
			print_inet_ntop(ip_hdr);
			printf("Payload : %dByte\n", payload_length);
			
			if (payload_length == 0) {
				continue;
			} else if (payload_length < 10) {
				for (int i = header_length; i < header_length + payload_length; i++) {
					printf("|%02x", packet[i]);
				}
			} else {
				for (int i = header_length; i < header_length + 10; i++) {
					printf("|%02x", packet[i]);
				}
			}
			
			printf("|\n\n");
		}
		


		
	}

	pcap_close(pcap);
}
