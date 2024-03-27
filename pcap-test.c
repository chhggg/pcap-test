#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void mac_print(uint8_t* addr){
    printf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void data_print(uint8_t* data, int datalen){
	if (datalen <= 0) printf("None");
	else{
		if(datalen > 20) datalen = 20;
		for (int i=0; i<datalen; i++){
			printf("%02x ", *data);
			data++;
		}
	}
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		/* Get Ethernet hdr */
		struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr *)packet;
		/* Check Ether type */
		if(ntohs(ethernet->ether_type) != ETHERTYPE_IP) continue;

		/* Get IP hdr */
		struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *) (packet + sizeof(*ethernet));
		/* Check Protocol */
		if(ipv4->ip_p != IPPROTO_TCP) continue;

		/* Get TCP hdr */
		struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *) (packet + sizeof(*ethernet) + sizeof(*ipv4));

		/* Get Data */
		uint8_t *data = (uint8_t*)(packet + sizeof(*ethernet) + sizeof(*ipv4) + sizeof(*tcp));
		int datalen = (int)(header->caplen) - (sizeof(*ethernet) + sizeof(*ipv4) + sizeof(*tcp));


		/* Mac address src -> dst */
		printf("[ MAC ] ");
		mac_print(ethernet->ether_shost);
		printf(" -> ");
		mac_print(ethernet->ether_dhost);

		/* IP : Port src -> dst */
		printf("\n[ IP ] ");
		printf("%s:%u", inet_ntoa(ipv4->ip_src),ntohs(tcp->th_sport));
		printf(" -> ");
		printf("%s:%u", inet_ntoa(ipv4->ip_dst),ntohs(tcp->th_dport));

		/* Data */
		printf("\n[ DATA ] ");
		data_print(data, datalen);


		printf("\n=====================================================\n\n");
	}


	pcap_close(pcap);
}

