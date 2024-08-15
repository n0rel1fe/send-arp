#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h> // 네트워크 인터페이스 정보를 가져오기 위한 헤더 파일
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int get_wlan_ip(char *ip) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (strncmp(ifa->ifa_name, "wlan", 4) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);

                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

int get_wlan_mac(unsigned char *mac) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (strncmp(ifa->ifa_name, "wlan", 4) == 0) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock == -1) {
                perror("socket");
                freeifaddrs(ifaddr);
                return -1;
            }

            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
            ifr.ifr_name[IFNAMSIZ-1] = '\0';

            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
                close(sock);
                freeifaddrs(ifaddr);
                return 0;
            } else {
                perror("ioctl");
                close(sock);
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

void send_arp_request(pcap_t *handle, const char *src_ip, const char *dst_ip, const unsigned char *src_mac, const unsigned char *broadcast_mac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(broadcast_mac);     // 브로드캐스트 주소
    packet.eth_.smac_ = Mac(src_mac);           // 로컬 MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);     // ARP 패킷

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);    // Ethernet
    packet.arp_.pro_ = htons(EthHdr::Ip4);      // IPv4
    packet.arp_.hln_ = Mac::SIZE;               // MAC 주소 크기
    packet.arp_.pln_ = Ip::SIZE;                // IP 주소 크기
    packet.arp_.op_ = htons(ArpHdr::Request);   // ARP 요청

    packet.arp_.smac_ = Mac(src_mac);           // 로컬 MAC 주소
    packet.arp_.sip_ = htonl(Ip(src_ip));       // 로컬 IP 주소
    packet.arp_.tmac_ = Mac::nullMac();         // 타겟 MAC 주소(아직 알 수 없음)
    packet.arp_.tip_ = htonl(Ip(dst_ip));       // 타겟 IP 주소

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int receive_arp_reply(pcap_t *handle, const char *target_ip, unsigned char *mac_address) {
    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // 타임아웃
        if (res == -1 || res == -2) break; // 에러 혹은 패킷 끝

        EthArpPacket *eth_arp_packet = (EthArpPacket *)packet;

        if (ntohs(eth_arp_packet->eth_.type_) == EthHdr::Arp &&
            ntohs(eth_arp_packet->arp_.op_) == ArpHdr::Reply) {
            if (ntohl(eth_arp_packet->arp_.sip_) == Ip(target_ip)) {
                memcpy(mac_address, eth_arp_packet->arp_.smac_.data(), 6);
                return 0;
            }
        }
    }
    return -1;
}

int get_mac_about_ip(pcap_t *handle, const char *iface, const char *ip, unsigned char *mac_address) {
    unsigned char local_mac[6];
    unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (get_wlan_mac(local_mac) == -1) {
        fprintf(stderr, "Failed to get local MAC address\n");
        return -1;
    }

    char local_ip[INET_ADDRSTRLEN];
    if (get_wlan_ip(local_ip) == -1) {
        fprintf(stderr, "Failed to get local IP address\n");
        return -1;
    }

    // ARP 요청 패킷을 보냄
    send_arp_request(handle, local_ip, ip, local_mac, broadcast_mac);

    // ARP 응답을 기다리고 수신하여 MAC 주소 추출
    if (receive_arp_reply(handle, ip, mac_address) == -1) {
        fprintf(stderr, "Failed to receive ARP reply\n");
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char iface[] = "wlan0";
    unsigned char gateway_mac[6];
    unsigned char sender_mac[6];

	char local_ip[INET_ADDRSTRLEN] = {0};  // IP 주소를 저장할 변수
    unsigned char local_mac[6] = {0}; 

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    for (int i = 2; i < argc ; i +=2)
    {

        // IP 주소로 MAC 주소 얻기
        get_mac_about_ip(handle, iface, argv[i], sender_mac);
        get_mac_about_ip(handle, iface, argv[i+1], gateway_mac);
        
        get_wlan_ip(local_ip);
        get_wlan_mac(local_mac);
        

        char sender_mac_str[18];
        char target_mac_str[18];
        char local_mac_str[18];
        
        snprintf(sender_mac_str, sizeof(sender_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                sender_mac[0], sender_mac[1], sender_mac[2],
                sender_mac[3], sender_mac[4], sender_mac[5]);

        snprintf(target_mac_str, sizeof(target_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                gateway_mac[0], gateway_mac[1], gateway_mac[2],
                gateway_mac[3], gateway_mac[4], gateway_mac[5]);
        
        snprintf(local_mac_str, sizeof(local_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                local_mac[0], local_mac[1], local_mac[2],
                local_mac[3], local_mac[4], local_mac[5]);
                
        

        EthArpPacket packet;

        packet.eth_.dmac_ = Mac(sender_mac_str);
        packet.eth_.smac_ = Mac(local_mac_str);    
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(local_mac_str);
        packet.arp_.sip_ = htonl(Ip(argv[i+1]));
        packet.arp_.tmac_ = Mac(sender_mac_str);
        packet.arp_.tip_ = htonl(Ip(argv[i]));


        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }	

    printf("SENDER MAC Address of %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
        iface,
        sender_mac[0], sender_mac[1], sender_mac[2],
        sender_mac[3], sender_mac[4], sender_mac[5]);

    printf("TARGET MAC Address of %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
        iface,
        gateway_mac[0], gateway_mac[1], gateway_mac[2],
        gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    pcap_close(handle);
    return 0;
}
