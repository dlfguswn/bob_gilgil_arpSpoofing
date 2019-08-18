#include "protocol_header.h"

void getMyMacAddr(uint8_t* mac_address){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1){}

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
            strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                        success = 1;
                        break;
                    }
                }
            }
            else { /* handle error */ }
        }

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
}

void getMyIPAddress(uint32_t* ip, char* interface){
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if((strcmp(ifa->ifa_name, interface)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            in_addr inetAddr_tmp;
            inet_aton(host, &inetAddr_tmp);
            *ip = (inetAddr_tmp.s_addr);

            break;
        }
    }
    freeifaddrs(ifaddr);
}

void makeTargetList(char* s_ip, char* t_ip, uint32_t* senderIP, u_int32_t* targetIP){
    in_addr ip_addr_tmp;

    inet_aton(s_ip, &ip_addr_tmp);
    *senderIP = ip_addr_tmp.s_addr;

    inet_aton(t_ip, &ip_addr_tmp);
    *targetIP = ip_addr_tmp.s_addr;
}

void assembleARPPacket(struct ARP_Packet* arp_packet, uint8_t* s_mac, uint32_t s_ip, uint8_t* d_mac, uint32_t t_ip, short opcode){
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_arp_hdr arp_hdr;

    // Make the ARP Broadcast Packet
        //1. Broadcast ETH
    memcpy(eth_hdr.ether_dhost, d_mac, 6);
    memcpy(eth_hdr.ether_shost, s_mac, 6);
    eth_hdr.ether_type = htons(0x0806);

        //2. ARP Request
    arp_hdr.arp_hrd_type = htons(0x01);
    arp_hdr.arp_proto = htons(0x0800);
    arp_hdr.arp_hrd_size = 0x6;
    arp_hdr.arp_proto_size = 0x4;
    arp_hdr.arp_op = htons(opcode); //Opcode

    memcpy(arp_hdr.s_hw_addr, s_mac, 6);
    memcpy(arp_hdr.t_hw_addr, d_mac, 6);
    arp_hdr.s_ip_addr = s_ip;
    arp_hdr.t_ip_addr = t_ip;

    memcpy(&arp_packet->eth_hdr, &eth_hdr, sizeof(libnet_ethernet_hdr));
    memcpy(&arp_packet->arp_hdr, &arp_hdr, sizeof(libnet_arp_hdr));
}

void recvARP(pcap_t* pcap_handle, pcap_pkthdr* pcap_header, u_short opcode, uint32_t senderIP, uint8_t* extractMac, u_char* buf){
    const u_char* pcap_payload = NULL;
    while(1){   //Waiting the target response
        int res = pcap_next_ex(pcap_handle, &pcap_header, &pcap_payload);
        struct libnet_ethernet_hdr* eth_hdr;
        struct libnet_arp_hdr* arp_hdr;

        eth_hdr = (libnet_ethernet_hdr*)pcap_payload;
        arp_hdr = (libnet_arp_hdr*)&pcap_payload[sizeof(libnet_ethernet_hdr)];

        if(ntohs(eth_hdr->ether_type) == 0x0806
                && ntohs(arp_hdr->arp_op) == opcode
                && arp_hdr->s_ip_addr == senderIP){
            if( extractMac != NULL){
                for(int i = 0; 6 > i; i++){
                    extractMac[i] = arp_hdr->s_hw_addr[i];
                }
            }
            if( buf != NULL){
                strcpy((char*)buf, (char*)pcap_payload);
            }
            return;
        }
    }
}
