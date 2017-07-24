#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <pcap/pcap.h>
#include <string.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct my_ether{
	u_char  address_d[ETHER_ADDR_LEN];
	u_char  address_s[ETHER_ADDR_LEN];
	u_short type;
};
struct my_ip{
	u_int8_t ip_vhl;
#define IP_V(ip)  (((ip)->ip_vhl & 0xf0)>>4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
	u_int8_t ip_tos;
	u_int16_t ip_len;
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_p;
	u_int16_t ip_sum;
	struct in_addr ip_src, ip_dst;
};
static u_int16_t checksum(u_int16_t *ptr,int size){
	register long  sum=0;
	while(size>1){
		sum+=* ptr++;
		size-=sizeof(u_int16_t);
	}
	if(size){
		sum+=*(u_int16_t*)ptr;
	}
	sum=(sum>>16)+(sum & 0xffff);
	sum+=(sum>>16);
	return ((u_int16_t)(~sum));
}
void my_ip_header(u_char *arg, struct pcap_pkthdr* pthdr, u_char *packet){
	static int number=0;  u_int16_t  test=0;
	struct my_ip *header;
	header=(struct my_ip*)(packet+sizeof(struct my_ether));
	test=checksum((u_int16_t*)header,IP_HL(header));
	printf("%d: ",++number);
	printf("IP-address destination:%s\n",inet_ntoa(header->ip_dst));
	printf("IP-address sender:%s\n",inet_ntoa(header->ip_src));
	printf("Protocol:%d\n",header->ip_p);
	printf("HL IP:%d %d\n",IP_V(header),IP_HL(header));
	printf("Check summ:%d\n",header->ip_sum);
	printf("My check summ:%d\n",test);

}
void my_ether_header(u_char *arg, struct pcap_pkthdr* pthdr, u_char *packet){
	static int number=0, i;
	struct my_ether *header;
	u_char *ptr;
	header=(struct my_ether*)packet;
	printf("Hendline length: %d\n", pthdr->len);
	printf("MAC-address destinaion: %s\n",ether_ntoa((struct ether_addr*)header->address_d));
	printf("MAC-address sender: %s\n",ether_ntoa((struct ether_addr*)header->address_s));
	printf("Type: %d\n",header->type);
	for(i=0; i< pthdr->len; i++){
		if(isprint(packet[i])){
			printf("%c", packet[i]);
		}
		else
			printf(".");
	}
	printf("\n");
	printf("\n");
}
void print_pack(u_char *arg, struct pcap_pkthdr* pthdr, u_char *packet){
	my_ip_header(arg,pthdr,packet);
	my_ether_header(arg, pthdr, packet);
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
	pcap_loop(pcap_fd,5,(pcap_handler)print_pack,user);
}

