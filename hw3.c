#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define MAX_MACLEN 100

typedef struct pcap_pkthdr pcap_pkthdr;
typedef struct ether_header ether_header;
typedef struct tcphdr tcphdr;
typedef struct udphdr udphdr;
typedef struct ip ip;



void help(){
    printf("./hw3 file\n");
    exit(1);
}

void print_cnt(char *ptr){
    int line_len = 50;
    int length = strlen(ptr);
    int left = (line_len - length) / 2;
    int right = line_len - length - left;
    for(int i = 0;i < left;i++){
        printf("-");
    }
    printf("%s",ptr);
    for(int i = 0;i < right;i++){
        printf("-");
    }
    printf("\n");
}

char* mac_ntoa(u_char *n){                          //store mac address
    char *mac = malloc(sizeof(char) * MAX_MACLEN);
    for(int i = 0;i < 6;i++){
        char *tmp = malloc(sizeof(char) * 2);
        sprintf(tmp, "%02x", n[i]);
        if(i) strcat(mac, ":");
        strcat(mac, tmp);
    }
    return mac;
}

int main(int argc,char** argv){
    if(argc < 2){
        help();
        exit(1);
    }

    char* filename;
    filename = strdup(argv[argc-1]);
    char errbuf[PCAP_BUF_SIZE] = "\0";

    pcap_t *handler = pcap_open_offline(filename,errbuf);   //open offline handle
    if(!handler){
        fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
    exit(1);
    }

    int packet_cnt = 0;
    while(1){
        pcap_pkthdr *packet_header;                         //timestamp, portion length, sum of length 
        ether_header *eth_header;
        tcphdr *tcp_header;
        udphdr *udp_header;
        time_t time_t_tmp;
        u_char *packet;

        /*start capture*/
        int ret = pcap_next_ex(handler, &packet_header, (const u_char **)&packet);  
        if(ret == 0){
            continue;
        }
        else if(ret == -2){                                 //no packet
            char line[100];
            sprintf(line, "End of %s",filename);
            print_cnt(line);
            break;
        }
        else if(ret == -1){                                 //error
            printf("pcap_next_ex error\n");
            exit(1);
        }

        time_t_tmp = packet_header->ts.tv_sec;
        struct tm ts = *localtime(&time_t_tmp);
        char str_time[50];
        strftime(str_time, sizeof(str_time), "%a %Y-%m-%d %H:%M:%S", &ts);  //store time format

        eth_header = (ether_header *)packet;

        char mac_src[MAX_MACLEN];
        char mac_des[MAX_MACLEN];
        strcpy(mac_src, mac_ntoa(eth_header->ether_shost));
        strcpy(mac_des, mac_ntoa(eth_header->ether_dhost));

        char P_cnt[100];
        sprintf(P_cnt, "Packet count = %d", ++packet_cnt);
        //printf("%s\n",P_cnt);
        print_cnt(P_cnt);

        printf("\n<Info>\n");
        printf("┌───────────────────┬─────────────────────────┐\n");
        printf("│ Packet number     │                    %4d │\n", packet_cnt);       
        printf("├───────────────────┼─────────────────────────┤\n");
        printf("│ Time              │ %s │\n", str_time);       
        printf("├───────────────────┼─────────────────────────┤\n");
        printf("│ Length            │                   %5d │\n", packet_header->len);       
        printf("├───────────────────┼─────────────────────────┤\n");
        printf("│ Capture Length    │                   %5d │\n", packet_header->caplen);       
        printf("└───────────────────┴─────────────────────────┘\n");


        printf("\n<MAC>\n");
        printf("┌─────────────────────────┬───────────────────┐\n");
        printf("│ MAC Sourse address      │ %15s │\n", mac_src);       
        printf("├─────────────────────────┼───────────────────┤\n");
        printf("│ MAC Destination address │ %15s │\n", mac_des);       
        printf("└─────────────────────────┴───────────────────┘\n");
 
        unsigned short type = ntohs(eth_header->ether_type);
        ip *ip_header = (ip *)(packet + ETHER_HDR_LEN);

        printf("\n<Ethernet type>\n");
        if(type == ETHERTYPE_IP){
            char ip_src[INET_ADDRSTRLEN];
            char ip_des[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), ip_src, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), ip_des, INET_ADDRSTRLEN);

            printf("┌──────────────────┬────────┐\n");
            printf("│ Ethernet type    │   IP   │\n");       
            printf("└──────────────────┴────────┘\n");

            printf("\n<IP>\n");
            printf("┌────────────────────────┬─────────────────┐\n");
            printf("│ IP Sourse address      │ %15s │\n", ip_src);       
            printf("├────────────────────────┼─────────────────┤\n");
            printf("│ IP Destination address │ %15s │\n", ip_des);       
            printf("└────────────────────────┴─────────────────┘\n");

            if(ip_header->ip_p == IPPROTO_UDP){
                udp_header = (udphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
                printf("\n<PORT>\n");
                printf("┌──────────────────┬────────┐\n");
                printf("│ Protocol         │  UDP   │\n"); 
                printf("├──────────────────┼────────┤\n");
                printf("│ Sourse Port      │ %6d │\n", ntohs(udp_header->uh_sport));       
                printf("├──────────────────┼────────┤\n");
                printf("│ Destination Port │ %6d │\n", ntohs(udp_header->uh_dport));       
                printf("└──────────────────┴────────┘\n");
            }
            else if(ip_header->ip_p == IPPROTO_TCP){
                tcp_header = (tcphdr *)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);
                printf("\n<PORT>\n");
                printf("┌──────────────────┬────────┐\n");
                printf("│ Protocol         │  TCP   │\n");       
                printf("├──────────────────┼────────┤\n");
                printf("│ Sourse Port      │ %6d │\n", ntohs(tcp_header->th_sport));       
                printf("├──────────────────┼────────┤\n");
                printf("│ Destination Port │ %6d │\n", ntohs(tcp_header->th_dport));       
                printf("└──────────────────┴────────┘\n");
            }
        }
        else if(type == ETHERTYPE_ARP){
            printf("┌──────────────────┬────────┐\n");
            printf("│ Ethernet type    │  ARP   │\n");       
            printf("└──────────────────┴────────┘\n");
        }
        else if(type == ETHERTYPE_PUP){
            printf("┌──────────────────┬────────┐\n");
            printf("│ Ethernet type    │  PUP   │\n");       
            printf("└──────────────────┴────────┘\n"); 
        }
        else if(type == ETHERTYPE_IPV6) {
            printf("┌──────────────────┬────────┐\n");
            printf("│ Ethernet type    │ IPv6   │\n");       
            printf("└──────────────────┴────────┘\n");  
        }
        else {
            printf("┌──────────────────┬────────────┐\n");
            printf("│ Ethernet type    │ No support │\n");       
            printf("└──────────────────┴────────────┘\n"); 
        }
    }
    return 0;
}