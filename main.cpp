#include <pcap.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <stdio.h>
#include <stdlib.h>

#pragma pack(push, 1)
struct FwdPkt
{
    EthHdr eth_;
    libnet_ipv4_hdr ip_;
    libnet_tcp_hdr tcp_;
};

struct BwdPkt
{
    EthHdr eth_;
    libnet_ipv4_hdr ip_;
    libnet_tcp_hdr tcp_;
    char msg[53];
};

struct PsdHdr
{
    in_addr saddr;
    in_addr daddr;
    u_char mbz;
    u_char ptcl;
    u_short tcpl;
};

struct FwdTcpBuf
{
    PsdHdr psd_;
    libnet_tcp_hdr tcp_;
};

struct BwdTcpBuf
{
    PsdHdr psd_;
    libnet_tcp_hdr tcp_;
    char msg[53];
};
#pragma pack(pop)

void usage()
{
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int getMyMac(char *if_name, Mac *my_mac)
{
    // REFERENCE: https://stackoverflow.com/questions/10593736/mac-address-from-interface-on-os-x-c

    int mib[6];
    size_t len;
    char *buf;
    unsigned char *ptr;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    if ((mib[5] = if_nametoindex(if_name)) == 0)
    {
        perror("if_nametoindex error");
        return -1;
    }

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
    {
        perror("sysctl 1 error");
        return -1;
    }

    if ((buf = (char *)malloc(len)) == NULL)
    {
        perror("malloc error");
        return -1;
    }

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
    {
        perror("sysctl 2 error");
        return -1;
    }

    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    // ptr = (unsigned char *)LLADDR(sdl);
    // printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *ptr, *(ptr + 1), *(ptr + 2),
    //        *(ptr + 3), *(ptr + 4), *(ptr + 5));
    memcpy((void *)my_mac, LLADDR(sdl), sizeof(Mac));

    return 0;
}

bool isTarget(char *payload, int payload_len, char *pattern)
{
    int pattern_len = strlen(pattern);
    for (int i = 0; i < payload_len && i + pattern_len <= payload_len; i++)
    {
        if (memcmp(payload + i, pattern, pattern_len) == 0)
        {
            return true;
        }
    }

    return false;
}

// REFERENCE - https://android.googlesource.com/platform/system/core/+/master/libnetutils/checksum.c

/* function: ip_checksum_add
 * adds data to a checksum. only known to work on little-endian hosts
 * current - the current checksum (or 0 to start a new checksum)
 *   data        - the data to add to the checksum
 *   len         - length of data
 */
uint32_t ip_checksum_add(uint32_t current, const uint16_t *data, int len)
{
    uint32_t checksum = current;
    int left = len;

    while (left > 1)
    {
        checksum += *data;
        data++;
        left -= 2;
    }
    if (left)
    {
        checksum += *(uint8_t *)data;
    }

    return checksum;
}

/* function: ip_checksum_fold
 * folds a 32-bit partial checksum into 16 bits
 *   temp_sum - sum from ip_checksum_add
 *   returns: the folded checksum in network byte order
 */
uint16_t ip_checksum_fold(uint32_t temp_sum)
{
    while (temp_sum > 0xffff)
    {
        temp_sum = (temp_sum >> 16) + (temp_sum & 0xFFFF);
    }
    return temp_sum;
}

/* function: ip_checksum_finish
 * folds and closes the checksum
 *   temp_sum - sum from ip_checksum_add
 *   returns: a header checksum value in network byte order
 */
uint16_t ip_checksum_finish(uint32_t temp_sum)
{
    return ~ip_checksum_fold(temp_sum);
}

/* function: ip_checksum
 * combined ip_checksum_add and ip_checksum_finish
 *   data - data to checksum
 *   len  - length of data
 */
uint16_t ip_checksum(const uint16_t *data, int len)
{
    // TODO: consider starting from 0xffff so the checksum of a buffer entirely consisting of zeros
    // is correctly calculated as 0.
    uint32_t temp_sum;

    temp_sum = ip_checksum_add(0, data, len);
    return ip_checksum_finish(temp_sum);
}

// REFERENCE - https://www.winpcap.org/pipermail/winpcap-users/2007-July/001984.html

u_short CheckSum(u_short *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(u_short);
    }
    if (size)
        cksum += *(u_char *)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (u_short)(~cksum);
}

int fwdBlock(pcap_t *handle, libnet_tcp_hdr *tcp_hdr, const u_char *packet, int packet_size, Mac my_mac, int payload_len)
{
    u_char *fwd_packet_ = (u_char *)malloc(packet_size);
    memcpy(fwd_packet_, packet, packet_size);
    FwdPkt *fwd_packet = (FwdPkt *)fwd_packet_;

    fwd_packet->eth_.smac_ = my_mac;

    fwd_packet->ip_.ip_len = htons(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr));
    fwd_packet->ip_.ip_sum = 0;
    fwd_packet->ip_.ip_sum = ip_checksum((uint16_t *)&fwd_packet->ip_, sizeof(libnet_ipv4_hdr));

    fwd_packet->tcp_.th_seq = htonl(ntohl(tcp_hdr->th_seq) + payload_len);
    fwd_packet->tcp_.th_off = sizeof(libnet_tcp_hdr) >> 2;
    fwd_packet->tcp_.th_flags = TH_RST | TH_ACK;

    fwd_packet->tcp_.th_sum = 0;
    FwdTcpBuf fwd_tcp_buffer;
    fwd_tcp_buffer.psd_.saddr = fwd_packet->ip_.ip_src;
    fwd_tcp_buffer.psd_.daddr = fwd_packet->ip_.ip_dst;
    fwd_tcp_buffer.psd_.mbz = 0;
    fwd_tcp_buffer.psd_.ptcl = IPPROTO_TCP;
    fwd_tcp_buffer.psd_.tcpl = htons(sizeof(libnet_tcp_hdr));
    memcpy(&fwd_tcp_buffer.tcp_, &fwd_packet->tcp_, sizeof(libnet_tcp_hdr));
    fwd_packet->tcp_.th_sum = CheckSum((u_short *)&fwd_tcp_buffer, sizeof(FwdTcpBuf));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(fwd_packet), sizeof(FwdPkt));
    free(fwd_packet_);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }

    return 0;
}

int bwdBlock(pcap_t *handle, libnet_tcp_hdr *tcp_hdr, const u_char *packet, int packet_size, Mac my_mac, int payload_len)
{
    u_char *bwd_packet_ = (u_char *)malloc(packet_size + 53);
    memcpy(bwd_packet_, packet, packet_size);
    BwdPkt *bwd_packet = (BwdPkt *)bwd_packet_;

    struct libnet_ethernet_hdr *eth_hdr = (libnet_ethernet_hdr *)(packet);
    bwd_packet->eth_.dmac_ = Mac(eth_hdr->ether_shost);
    bwd_packet->eth_.smac_ = my_mac;

    bwd_packet->ip_.ip_len = htons(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr) + 53);
    bwd_packet->ip_.ip_ttl = 128;
    in_addr tmp_ip = bwd_packet->ip_.ip_src;
    bwd_packet->ip_.ip_src = bwd_packet->ip_.ip_dst;
    bwd_packet->ip_.ip_dst = tmp_ip;
    bwd_packet->ip_.ip_sum = 0;
    bwd_packet->ip_.ip_sum = ip_checksum((uint16_t *)&bwd_packet->ip_, sizeof(libnet_ipv4_hdr));

    uint16_t tmp_port = bwd_packet->tcp_.th_sport;
    bwd_packet->tcp_.th_sport = bwd_packet->tcp_.th_dport;
    bwd_packet->tcp_.th_dport = tmp_port;
    bwd_packet->tcp_.th_seq = bwd_packet->tcp_.th_ack;
    bwd_packet->tcp_.th_ack = htonl(ntohl(tcp_hdr->th_seq) + payload_len);
    bwd_packet->tcp_.th_off = sizeof(libnet_tcp_hdr) >> 2;
    bwd_packet->tcp_.th_flags = TH_FIN | TH_ACK;

    memcpy(bwd_packet->msg, "HTTP/1.0 302 Redirect\nLocation: http://warning.or.kr\n", 53);

    bwd_packet->tcp_.th_sum = 0;
    BwdTcpBuf bwd_tcp_buffer;
    bwd_tcp_buffer.psd_.saddr = bwd_packet->ip_.ip_src;
    bwd_tcp_buffer.psd_.daddr = bwd_packet->ip_.ip_dst;
    bwd_tcp_buffer.psd_.mbz = 0;
    bwd_tcp_buffer.psd_.ptcl = IPPROTO_TCP;
    bwd_tcp_buffer.psd_.tcpl = htons(sizeof(libnet_tcp_hdr) + 53);
    memcpy(&bwd_tcp_buffer.tcp_, &bwd_packet->tcp_, sizeof(libnet_tcp_hdr) + 53);
    bwd_packet->tcp_.th_sum = CheckSum((u_short *)&bwd_tcp_buffer, sizeof(BwdTcpBuf));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(bwd_packet), sizeof(BwdPkt));
    free(bwd_packet_);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }

    return 0;
}

int block(pcap_t *handle, const u_char *packet, Mac my_mac, int payload_len)
{
    struct libnet_ipv4_hdr *ip_hdr = (libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
    int ip_len = ip_hdr->ip_hl << 2;
    struct libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr *)((char *)ip_hdr + ip_len);

    int packet_size = sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr); // 14 + 20 + 20 = 54

    if (fwdBlock(handle, tcp_hdr, packet, packet_size, my_mac, payload_len) == -1)
    {
        printf("ERR: fwdBlock()\n");
        return -1;
    }

    if (bwdBlock(handle, tcp_hdr, packet, packet_size, my_mac, payload_len) == -1)
    {
        printf("ERR: bwdBlock()\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac my_mac;
    if (getMyMac(dev, &my_mac) == -1)
    {
        printf("ERR: getMyMac()\n");
        pcap_close(handle);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct libnet_ipv4_hdr *ip_hdr = (libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
        if (ip_hdr->ip_p != IPPROTO_TCP)
        {
            continue;
        }

        int ip_len = ip_hdr->ip_hl << 2;
        struct libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr *)((char *)ip_hdr + ip_len);

        int tcp_len = tcp_hdr->th_off << 2;
        char *payload = (char *)(tcp_hdr) + tcp_len;

        int tot_len = ntohs(ip_hdr->ip_len);
        int payload_len = tot_len - ip_len - tcp_len;
        if (payload_len == 0)
        {
            continue;
        }

        char *pattern = argv[2];
        if (isTarget(payload, payload_len, pattern))
        {
            if (block(handle, packet, my_mac, payload_len) == -1)
            {
                printf("ERR: block()\n");
                pcap_close(handle);
                return -1;
            }
        }
    }

    pcap_close(handle);
    return 0;
}
