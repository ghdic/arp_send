#include <netinet/ether.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <pcap.h>

#define ETHERTYPE_IPV4 0x0800

unsigned char MY_MAC_ADDR[18]="";
unsigned char UR_MAC_ADDR[18]="";
unsigned char ROUT_MAC_ADDR[18]="";

unsigned char MY_IP[16]="192.168.190.130";
unsigned char UR_IP[16]="192.168.31.253";
unsigned char ROUT_IP[16]="";


unsigned char *packet;

typedef struct Ether_header{
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
}Ether_header;
/*
typedef struct arphdr{
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
}arphdr;
*/
typedef struct Ether_arp{
    arphdr arp_hdr;
    uint8_t arp_sha[6];
    uint8_t arp_spa[4];
    uint8_t arp_tha[6];
    uint8_t arp_tpa[4];
}Ether_arp;

typedef struct arp_packet{
    Ether_header ether;
    Ether_arp arp;
}arp_packet;

char * get_my_mac()
{
    struct ifreq *ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    struct ifconf ifcfg;
    int fd;
    int n;
    int numreqs = 30;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifcfg, 0, sizeof(ifcfg));

    ifcfg.ifc_buf = NULL;
    ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
    ifcfg.ifc_buf = (char *)malloc(ifcfg.ifc_len);

    for(;;)

    {
        ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
        ifcfg.ifc_buf = (char *)realloc(ifcfg.ifc_buf, ifcfg.ifc_len);
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifcfg) < 0)
        {
            perror("SIOCGIFCONF ");
            exit(0);
        }
        break;
    }

    ifr = ifcfg.ifc_req;

    for (n = 0; n < ifcfg.ifc_len; n+= sizeof(struct ifreq))
    {
        printf("[%s]\n", ifr->ifr_name);
        sin = (struct sockaddr_in *)&ifr->ifr_addr;
        printf("IP    %s\n", inet_ntoa(sin->sin_addr));

        if ( ntohl(sin->sin_addr.s_addr) == INADDR_LOOPBACK)
        {
            printf("Loop Back\n");
        }
        else
        {
            ioctl(fd, SIOCGIFHWADDR, (char *)ifr);
            sa = &ifr->ifr_hwaddr;
            printf("MAC	%s \n", ether_ntoa((struct ether_addr *)sa->sa_data));

        }

        printf("\n");

        ifr++;

    }

    return ether_ntoa((struct ether_addr *)sa->sa_data);

}

char * get_my_ip()
{
    struct ifreq *ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    struct ifconf ifcfg;
    int fd;
    int n;
    int numreqs = 30;
    char * ip;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifcfg, 0, sizeof(ifcfg));

    ifcfg.ifc_buf = NULL;
    ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
    ifcfg.ifc_buf = (char *)malloc(ifcfg.ifc_len);

    for(;;)

    {
        ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
        ifcfg.ifc_buf = (char *)realloc(ifcfg.ifc_buf, ifcfg.ifc_len);
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifcfg) < 0)
        {
            perror("SIOCGIFCONF ");
            exit(0);
        }
        break;
    }

    ifr = ifcfg.ifc_req;

    for (n = 0; n < ifcfg.ifc_len; n+= sizeof(struct ifreq))
    {
        sin = (struct sockaddr_in *)&ifr->ifr_addr;
        printf("IP    %s\n", ip= inet_ntoa(sin->sin_addr));
        printf("IP    %s\n", ip);

        if ( ntohl(sin->sin_addr.s_addr) == INADDR_LOOPBACK)
        {
            printf("Loop Back\n");
        }
        else
        {
            return ip;

        }

        printf("\n");

        ifr++;

    }
    exit(-1);
}


Ether_header * save_my_ether_header(uint8_t * dest, uint8_t * source, uint16_t type){
   Ether_header * head=(Ether_header *)malloc(sizeof(Ether_header));
    memcpy(head->ether_dhost ,dest, 6);
    memcpy(head->ether_shost, source, 6);

    head->ether_type=htons(type);

    return head;
}


Ether_arp * save_ether_arp(uint8_t sha[], uint32_t spa, uint8_t tha[], uint32_t tpa, uint32_t op){
    Ether_arp * arp=(Ether_arp *)malloc(sizeof(Ether_arp));
    arp->arp_hdr.ar_hrd = ntohs(1);
    arp->arp_hdr.ar_pro = ntohs(ETHERTYPE_IPV4);
    arp->arp_hdr.ar_hln = 6;
    arp->arp_hdr.ar_pln = 4;
    arp->arp_hdr.ar_op = htons(op);

    memcpy(arp->arp_sha,sha,6);
    memcpy(arp->arp_spa,spa,4);
    if(tha)
    memcpy(arp->arp_tha,tha,6);
    else
    memset(arp->arp_tha,0x00,6);
    //sha spa?? why memcpy memset??
    memcpy(arp->arp_tpa,tpa,4);


    return arp;
}

void strtobuf(char * str, uint8_t mac[]){

    sscanf(str,"%x:%x:%x:%x:%x:%x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
}

uint8_t * send_pcap(char * dev, u_char * packet){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    Ether_header * ether;
    Ether_arp * arp;
    int a;

    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);

    if(pcap_sendpacket(handle, packet,sizeof(arp_packet))!=0){
        printf("Send failed!!\n");
        printf("%s\n",errbuf);
        exit(-1);
    }else{
        printf("Sending!!\n");
    }
    if(packet==NULL){
    while(1){
        a = pcap_next_ex(handle, &header, &packet);
        printf("Jacked a packet with length of [%d]\n", header->len);

        if(a==1){
            ether=(Ether_header *)packet;

            if(ntohs(ether->ether_type) == ETHERTYPE_ARP){
               arp = (Ether_arp *)(packet + 14);
               for(int i=0;i<header->len;i++){
                   printf("%02x%c",packet[i],((i+1)%16!=0)?' ':'\n');
               }
               printf("\n");
               printf("%x\n",ntohs(arp->arp_hdr.ar_op));
               if(nthos(arp->arp_hdr.ar_op)==ARPOP_REPLY){
                   printf("ARP REPLY!!\n");
                    pcap_close(handle);
                   return arp->arp_sha;
               }
            }
        }
    }
    }
    pcap_close(handle);
    return NULL;
}

int main(int argc, char *argv[]){
    u_char smac[6], dmac[6];
    u_int sip, dip;
    u_char *ptr;
    uint8_t tha[6]="";
    arp_packet arp_packet;
    Ether_header * ether;
    Ether_arp * arp;
    char * dev;
    if(argc==4){
        dev = argv[1];

    }
    else{
        printf("plz write <./exe><dev><senderIP><targetIP>\n");
        return -1;
    }

    ptr = (u_char *)&arp_packet;
    memset(&arp_packet,0x00,sizeof(arp_packet));

    strtobuf(get_my_mac(), smac);
    strtobuf("ff:ff:ff:ff:ff:ff",dmac);

    sip = inet_addr(get_my_ip());
    dip = inet_addr(argv[2]);
    arp_packet.ether = save_my_ether_header(dmac, smac, ETHERTYPE_ARP);
    arp_packet.arp = save_ether_arp(smac, sip, dmac, dip, ARPOP_REQUEST);

    memcpy(tha, send_pcap(dev, ptr), 8);

    for(int i=0;i<6;i++){
        printf("%x",tha[i]);
    }

    sip = inet_addr(argv[3]);
    free(arp_packet.ether);
    free(arp_packet.arp);
    arp_packet.ether = save_my_ether_header(dmac, smac, ETHERTYPE_ARP);
    arp_packet.arp = save_ether_arp(smac, sip, dmac, dip, ARPOP_REQUEST);

    printf("packet print >> \n");
    for(int i=0; i< sizeof(arp_packet); i++){
        printf("%02x%c",ptr[i],((i+1)%16!=0)?' ':'\n');
    }
    send_pcap(dev, ptr);

    return 0;
}

