#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <pcap/pcap.h>
#include <string.h>
#include <netinet/ether.h>
struct my_ether{
	u_char address_d[ETHER_ADDR_LEN];
	u_char address_s[ETHER_ADDR_LEN];
	u_short type;
};

void my_handler(u_char *arg, struct pcap_pkthdr* pthdr, u_char *packet){
	static int number=0, i;
	struct my_ether *header;
	u_char *ptr;
	header=(struct my_ether*)packet;
	printf("%d: ",++number);
	printf("Hendline length: %d\n", pthdr->len);
	ptr=header->address_d;
	i=ETHER_ADDR_LEN;
	printf("MAC-address destinaion: ");
	do{
			if(i!=1)
				printf("%x:",ptr[i]);
			else
				printf("%x",ptr[i]);
		i--;
	}while(i>0);
	printf("\n");
//	printf(" %s\n", header->address_d);
	ptr=header->address_s;
	i=ETHER_ADDR_LEN;
	printf("MAC-address sender: ");
	do{
                        if(i!=1)
                                printf("%x:",ptr[i]);
                        else
                                printf("%x",ptr[i]);
                i--;
        }while(i>0);
	printf("\n");
//	printf(" %s\n", header->address_s);
	printf("Type: %d\n",header->type);
	for(i=0; i< pthdr->len; i++){
		if(isprint(packet[i])){
			printf("%c", packet[i]);
		}
	}
	printf("\n");
	printf("\n");
}

int main()
{
	char *dev; char errbuf[PCAP_ERRBUF_SIZE];
	char buf_filter[]="ip"; u_char *user;
	bpf_u_int32 mask, net;
	pcap_t *pcap_fd;
	struct bpf_program fp;
	int test;

	dev=pcap_lookupdev(errbuf);
	printf("%s\n",dev);
	pcap_lookupnet(dev,&net,&mask,errbuf);
	printf("NET:%x\nMASK:%x\n\n", net, mask);
	pcap_fd=pcap_open_live(dev,BUFSIZ,1,0,errbuf);
	test=pcap_compile(pcap_fd,&fp,buf_filter,0,mask);
	pcap_setfilter(pcap_fd,&fp);
	pcap_loop(pcap_fd,5,(pcap_handler)my_handler,user);
}
