#include "netfilter-test.h"

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

int protocol_parsing(struct nfq_data* tb, void* host_data) {
	unsigned char* pkt_data;
	int size = nfq_get_payload(tb, &pkt_data);
	
	struct ip *ip_hdr = (struct ip *)(pkt_data); 

	u_int8_t ip_type = ip_hdr->ip_p;
	u_int8_t ip_offset = ip_hdr->ip_hl;

	// if protocol is not tcp, then return func
	if(ip_type != 6) return NF_ACCEPT;

	//if protocol is tcp, get tcp_hdr
	struct tcphdr *tcp_hdr = (struct tcphdr*)(pkt_data+ip_offset*4);

	unsigned short tcp_offset = tcp_hdr->doff;

	unsigned char* http_packet = (unsigned char*)(pkt_data+ip_offset*4+tcp_offset*4);
	int http_len = size - ip_offset*4 - tcp_offset*4;

	printf("\nPacket Info ====================================\n");

	//print ip addr
	char src_ip[16], dst_ip[16];
	char* tmp = inet_ntoa(ip_hdr->ip_src);
	strcpy(src_ip, tmp);
	tmp = inet_ntoa(ip_hdr->ip_dst);
	strcpy(dst_ip, tmp);

	printf("** IP **\n");
	printf("Src IP : %s\n", src_ip);
	printf("Dst IP : %s\n", dst_ip);

	unsigned short src_port = ntohs(tcp_hdr->source);
	unsigned short dst_port = ntohs(tcp_hdr->dest);
	
	printf("** TCP **\n");
	printf("Src Port : %d\n", src_port);
	printf("Dst Port : %d\n", dst_port);


	if (dst_port == 80 && http_len > 0)
		// HTTP Parsing	
		return http_parsing(http_packet, http_len, host_data);
	else return NF_ACCEPT;
}

int http_parsing(unsigned char* pkt_data, int size, void* host_data){
	// printf("%s\n", host_data);

	printf("%d\n", size);
	dump(pkt_data, size);

	printf("*** HTTP *** \n");
	char curr;
    int idx = 0;
    
    // strstr func
    // split by space. just find index of space. 
    do {
        curr = *(pkt_data+idx);
        if(curr == 0x0D) break;
        idx++;
    } while(curr);

    char get_str[idx+1];
    strncpy(get_str, (char*)pkt_data, idx);
    get_str[idx] = '\0';

    u_char* host_start = pkt_data+idx+2;
    idx = 0;
    do {
        curr = *(host_start + idx);
        if(curr == 0x0D) break;
        idx++;
    } while(curr);

    char host_str[idx+1];
    strncpy(host_str, (char*)host_start, idx);
    host_str[idx] = '\0';

	printf("%s\n", get_str);
	printf("%s\n", host_str);

	char host_name[idx - 5];
	strncpy(host_name, (char*)(host_str+6), idx-6);

	printf("**HOST : %s \n", host_name);

	if (strcmp((char*)host_data, host_name) == 0) {
		printf("Detected Malicious Host\n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}