#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define LEN_ETH 14

int main(int argc, char *argv[])
{
    pcap_t *handle;                   /* Session handle */
    char *dev;                        /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
    struct bpf_program fp;		      /* The compiled filter */
    char filter_exp[] = "port 80";    /* The filter expression */
    bpf_u_int32 mask;           	  /* Our netmask */
    bpf_u_int32 net;		          /* Our IP */
    struct pcap_pkthdr *header;	      /* The header that pcap gives us */
    const u_char *packet;		      /* The actual packet */
    time_t local_tv_sec;
    struct tm *ltime;
    char timestr[16];
    u_short port;
    int res, cnt=0;
    int LEN_IP, LEN_TCP, START_DATA;  /* Length ip, tcp, data */
    struct pkt_eth* eth_header;       /* The header that eth gives up */
    struct pkt_ip* ip_header;         /* The header that ip gives up */
    struct pkt_tcp* tcp_header;       /* The header that tcp gives up */
    u_char* startdata;                /* Start data area */
    char buf[32] = {0,};              /* Init buf */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    //    handle = pcap_open_live("dum0", BUFSIZ, 1, 1000, errbuf); ------------ change dum0
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    /* Retrieve the packets */
    while(res = pcap_next_ex(handle,&header,&packet)>=0){
        if(res == 0)
            continue;
        if(cnt) /* Cnt: 10, 9, 8, 7,... */
            break;
        cnt--;

        /* Print Ethernet packet */
        eth_header = (struct pkt_eth*)packet;
        printf("   <Ethernet Packet>\n");
        printf("Ethernet Length: %d\n",LEN_ETH);
        printf("Destination Mac Addr:\n");
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->eth_dhost[0],eth_header->eth_dhost[1],eth_header->eth_dhost[2],
                eth_header->eth_dhost[3],eth_header->eth_dhost[4],eth_header->eth_dhost[5]);
        printf("Source Mac Addr:\n");
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_header->eth_shost[0],eth_header->eth_shost[1],eth_header->eth_shost[2],
                eth_header->eth_shost[3],eth_header->eth_shost[4],eth_header->eth_shost[5]);
        printf("eth_type: %04x\n",ntohs(eth_header->eth_type));

        /* Print IP packet */
        ip_header = (struct pkt_ip*)(packet+LEN_ETH);
        if(eth_header->eth_type == 0x08){ /* 0x 08 00 == IP */
            printf("\n   <IP Packet>\n");
            LEN_IP = ((ip_header->ip_vl) & 0x0f) * 4;
            printf("IP Length: %d\n", LEN_IP); /* Extract Length */
            printf("Source IP Addr:\n");
            printf("%s\n",inet_ntop(AF_INET,&ip_header->ip_saddr, buf, sizeof(buf)));
            printf("Destination IP Addr:\n");
            printf("%s\n",inet_ntop(AF_INET,&ip_header->ip_daddr, buf, sizeof(buf)));
        }

        /* Print TCP packet */
        tcp_header = (struct pkt_tcp*)(packet+LEN_ETH+LEN_IP);

        if(ip_header->ip_p==0x06){ /* 0x 06 == TCP */
            LEN_TCP = ((tcp_header->tcp_offx2) >> 4) * 4;
            printf("\n   <TCP Packet>\n");
            printf("TCP Length: %d\n",LEN_TCP);
            printf("Source Port:\n");
            printf("%d\n",ntohs(tcp_header->tcp_sport));
            printf("Destination Port:\n");
            printf("%d\n",ntohs(tcp_header->tcp_dport));

            if((ntohs(tcp_header->tcp_sport)==80) || (ntohs(tcp_header->tcp_dport)==80)){
                /* Find data area */
                START_DATA = LEN_ETH + LEN_IP + LEN_TCP;
                startdata = (packet+START_DATA);
                printf("Extract 4Bytes from Data:\n%02x %02x %02x %02x\n\n",
                       startdata[0], startdata[1], startdata[2], startdata[3]);
            }
        }
    }

    /* And close the session */
    pcap_close(handle);

    return(0);
}
