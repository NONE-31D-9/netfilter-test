#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <arpa/inet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void dump(unsigned char* buf, int size);

int protocol_parsing(struct nfq_data *tb, void* host_data);

int http_parsing(unsigned char* pkt_data, int size, void* host_data);