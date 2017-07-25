#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <pcap/pcap.h>
#include <string.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct p_header{
	struct in_addr  p_ip_s;
	struct in_addr  p_ip_d;
	u_int8_t p;
	u_int8_t p_prot;
	u_short p_len;
}__attribute__((packed));

struct my_ether{
	u_char  address_d[ETHER_ADDR_LEN];
	u_char  address_s[ETHER_ADDR_LEN];
	u_short type;
}__attribute__((packed));

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
}__attribute__((packed));

struct my_tcp{
	u_short th_sport;
	u_short th_dport;
	u_int th_seq;
	u_int th_ack;
	u_short th_len_flaf;
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
}__attribute__((packed));

struct my_udp{
	u_short u_sport;
	u_short u_dport;
	u_short u_len;
	u_short u_sum;
}__attribute__((packed));


static unsigned short checksum(unsigned short *ptr,unsigned int size){
	register unsigned long  sum=0;
	while(size>1){
		sum+=*ptr++;
		size-=2;
	}
	if(size>0){
		sum+=((*ptr)&htons(0xFF00));
	}
	while(sum>>16){
	sum=(sum & 0xffff)+(sum>>16);
	}
	sum=~sum;
	return ((unsigned short)sum);
}

void my_udp_header(u_char *arg, struct pcap_pkthdr* pthdr, u_char *packet,  struct p_header *add){
	struct my_udp *header_udp; char*for_check, *tmp;
	header_udp=(struct my_udp*)(packet+sizeof(struct my_ether)+sizeof(struct my_ip));
	for_check=malloc(sizeof(struct p_header)+sizeof(struct my_udp));
        memcpy(for_check,add,sizeof(struct p_header));
        tmp=for_check+sizeof(struct p_header);
        memcpy(tmp,header_udp,sizeof(struct my_udp));
	printf("-------data_UDP-------\n");
	printf("UDP-port destination:%d\n",ntohs(header_udp->u_dport));
	printf("UDP-port sender:%d\n", ntohs(header_udp->u_sport));
	printf("UDP Cheksumm:%d\n", ntohs(header_udp->u_sum));
	printf("-----------------------\n");

}

void my_tcp_header(u_char *arg, struct pcap_pkthdr* pthdr, u_char *packet,struct p_header *add){
	struct my_tcp *header_tcp; char*for_check, *tmp;
	unsigned short test=0;
	header_tcp=(struct my_tcp*)(packet+sizeof(struct my_ether)+sizeof(struct my_ip));
	//test=header_tcp->th_sum; header_tcp->th_sum=0;
	for_check=malloc(sizeof(struct p_header)+sizeof(struct my_tcp));
	memcpy(for_check,add,sizeof(struct p_header));
	tmp=for_check+sizeof(struct p_header);
	memcpy(tmp,header_tcp,sizeof(struct my_tcp));
	test=checksum((unsigned short*)for_check,(unsigned int)add->p_len);
	printf("-------data_TCP-------\n");
	printf("TCP-port destination:%d\n",ntohs(header_tcp->th_dport));
	printf("TCP-port sender:%d\n", ntohs(header_tcp->th_sport));
	printf("TCP Cheksumm:%d\n", ntohs(header_tcp->th_sum));
	printf("My tcp cheksumm:%d\n", ntohs(test));
	printf("-----------------------\n");
}

void my_ip_header(u_char *arg, struct pcap_pkthdr* pthdr, u_char *packet){
	unsigned short  test=0;
	struct my_ip *header; struct p_header *add;
	header=(struct my_ip*)(packet+sizeof(struct my_ether));
	add=malloc(sizeof(struct p_header));
	add->p_ip_s=header->ip_src;
	add->p_ip_d=header->ip_dst;
	add->p=0;
	add->p_prot=header->ip_p;
	add->p_len=(u_short)(htons(header->ip_len)-IP_HL(header)<<2)+((u_short)(sizeof(struct p_header)));
	if(header->ip_p==6){
		my_tcp_header(arg, pthdr,packet,add);
	}
	if(header->ip_p==17){
		my_udp_header(arg,pthdr,packet,add);
	}
	test=header->ip_sum; header->ip_sum=0;
	header->ip_sum=checksum((unsigned short*)header,(unsigned int)IP_HL(header)<<2);
	printf("-------data_IP-------\n");
	printf("IP-address destination:%s\n",inet_ntoa(header->ip_dst));
	printf("IP-address sender:%s\n",inet_ntoa(header->ip_src));
	printf("Protocol:%d\n",header->ip_p);
	printf("IP Checksumm:%d\n",test);
	printf("My Ip checksumm:%d\n",header->ip_sum);
	printf("-----------------------\n");

}
void my_ether_header(u_char *arg, struct pcap_pkthdr* pthdr, u_char *packet){
	static int  i;
	struct my_ether *header;
	u_char *ptr;
	header=(struct my_ether*)packet;
	printf("-------data_Ethernet-------\n");
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
	char buf_filter[]="tcp"; u_char *user;
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
	pcap_loop(pcap_fd,2,(pcap_handler)print_pack,user);
}

