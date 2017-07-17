#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define LEN_ETH 14
#define WORD 4
int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    time_t local_tv_sec;
    struct tm *ltime;
    char timestr[16];
    int res, num, cnt;
    u_short port;
    int LEN_IP, LEN_TCP;

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
    res = pcap_next_ex(handle,&header,&packet);

    /* Choose packet number */
    printf("How many packets do you want?");
    scanf("%d",&num);
    cnt = num+1; /* Packet numbering */

    while(num){
        if(res){
            /* Print packet number */
            printf("===== Packet Number: %d =====\n",cnt-num);

            printf("Total len: %d\n",header->len);

            /* Print Ethernet packet */
            printf("   <Ethernet Packet>\n");
            printf("Ethernet Length: %d\n",LEN_ETH);
            printf("Destination Mac Addr:\n");
            printf("%02x:%02x:%02x:%02x:%02x:%02x",
                   *(packet+0),*(packet+1),*(packet+2),*(packet+3),*(packet+4),*(packet+5));
            printf("\nSource Mac Addr:\n");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                   *(packet+6),*(packet+7),*(packet+8),*(packet+9),*(packet+10),*(packet+11));

            /* Print IP packet */
            if(*(packet+12)==0x08 && *(packet+13)==0x00){ // 0x 08 00 == IP
                LEN_IP = (*(packet+14)&0x0f)*WORD; // Extract IP length
                printf("\n   <IP Packet>\n");
                printf("IP Length: %d\n",LEN_IP);
                printf("Source IP Addr:\n");
                printf("%d.%d.%d.%d\n",*(packet+26),*(packet+27),*(packet+28),*(packet+29));

                printf("Destination IP Addr:\n");
                printf("%d.%d.%d.%d\n",*(packet+30),*(packet+31),*(packet+32),*(packet+33));
            }
            /* Print TCP packet */
            if(*(packet+23)==0x06){ // 0x 06 == TCP
                LEN_TCP = header->len - LEN_ETH - LEN_IP;
                printf("\n   <TCP Packet>\n");
                printf("TCP Length: %d\n",LEN_TCP);
                port = *(packet+34);
                port = (port << 8) + *(packet+35);
                printf("Source Port:\n");
                printf("%d\n",port);

                printf("Destination Port:\n");
                port = *(packet+36);
                port = (port << 8) + *(packet+37);
                printf("%d\n",port);

                /* Find data area */
                printf("Extract 4Bytes from Data:\n%02x %02x %02x %02x\n\n",
                       *(packet+(header->len)),*(packet+(header->len)+1),
                       *(packet+(header->len)+2),*(packet+(header->len)+3));
            }
        }else
            printf("res is null");
        num--;
    }

    /* And close the session */
    pcap_close(handle);

    return(0);
 }
