#ifndef FUNCHEADER_H
#define FUNCHEADER_H

#endif // FUNCHEADER_H
#include <arpa/inet.h>
#include <pcap.h>

void getMyMacAddr(uint8_t* mac_address);
void getMyIPAddress(uint32_t* myIP, char* interface);
void makeTargetList(char* s_ip, char* t_ip, uint32_t* senderIP, u_int32_t* targetIP);
void assembleARPPacket(struct ARP_Packet* arp_packet, uint8_t* s_mac, uint32_t s_ip, uint8_t* d_mac, uint32_t t_ip, short opcode);
int recvARP(pcap_t* pcap_handle, pcap_pkthdr* pcap_header, u_short opcode, uint32_t senderIP, uint8_t* extractMac, u_char* buf);
