#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>

#define ETH_ALEN 6
struct ethhdr
{
    unsigned char   h_dest[ETH_ALEN]; /* destination eth addr */
    unsigned char   h_source[ETH_ALEN]; /* source ether addr    */
    unsigned short  h_proto;            /* packet type ID field */
};

struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;       /* header length */
    unsigned int ip_v:4;        /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;        /* version */
    unsigned int ip_hl:4;       /* header length */
#endif
    u_int8_t ip_tos;            /* type of service */
    u_short ip_len;         /* total length */
    u_short ip_id;          /* identification */
    u_short ip_off;         /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_int8_t ip_ttl;            /* time to live */
    u_int8_t ip_p;          /* protocol */
    u_short ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
  };

struct tcphdr
  {
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    u_int32_t th_seq;     /* sequence number */
    u_int32_t th_ack;     /* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;       /* (unused) */
    u_int8_t th_off:4;      /* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;      /* data offset */
    u_int8_t th_x2:4;       /* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN    0x01
#  define TH_SYN    0x02
#  define TH_RST    0x04
#  define TH_PUSH   0x08
#  define TH_ACK    0x10
#  define TH_URG    0x20
    u_int16_t th_win;       /* window */
    u_int16_t th_sum;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf); //reason error
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet); //handle=fread header=info,length
  }

  pcap_close(handle);
  return 0;
}
