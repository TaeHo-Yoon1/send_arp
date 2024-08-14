#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <regex>
#include <fstream>
#include <streambuf>
#include <vector>
#include <sstream>
#include <iomanip>
#include <set>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void getMyMacAddr(const char* interfaceName, Mac& my_mac, Ip& my_ip) {
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;

    string macAddr = "";
   

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
    } else {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) && !strcmp(ifa->ifa_name, interfaceName)) {
            struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
            my_ip = Ip(inet_ntoa(sa->sin_addr));
               
                ostringstream oss;
                struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                for (int i = 0; i < s->sll_halen; i++) {
                    oss << hex << setfill('0') << setw(2) << static_cast<int>(s->sll_addr[i]);
                    if (i != s->sll_halen - 1) oss << ":";
                }
                macAddr = oss.str();
            }
        }
        freeifaddrs(ifaddr);
        my_mac = Mac(macAddr);
    }
}

int my_send_arp(pcap_t* handle, Mac my_mac, Ip my_ip, Mac sender_mac, Ip sender_ip) {

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    
     while (true) {

        struct pcap_pkthdr* header;
        const u_char* replyPacket;

        res = pcap_next_ex(handle, &header, &replyPacket);
        if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("error");
			break;
		}


    }
    return res;
}



int send_me_arp(pcap_t* handle, Mac my_mac, Ip my_ip, Mac sender_mac, Ip sender_ip) {

    EthArpPacket packet;

    packet.eth_.dmac_ = my_mac;
	packet.eth_.smac_ = sender_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = sender_mac;
	packet.arp_.sip_ = htonl(sender_ip);
	packet.arp_.tmac_ = my_mac;
	packet.arp_.tip_ = htonl(my_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return res;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;


	pcap_close(handle);
}
