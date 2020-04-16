#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> // for close(sockfd), sleep(t)
#include <netdb.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef struct RTT_time {
    float min;
    float avg;
    float max;
    float stdev;
} RTT_time;

u_short ICMP_ID;

void compose_packet(char *packet, u_short seq_num);

u_short icmp_checksum(char *packet, int len);

void print_usage();
int main(int argc, char** argv) {
    char packet[64];
    struct addrinfo hints, *servinfo, *p;

    // for sending packets
    struct sockaddr whereto;
    socklen_t whereto_len;

    // for received packets
    struct sockaddr wherefrom;
    socklen_t wherefrom_len;

    int status;

    char *host;
    int ret, sockfd;
    struct icmp *icmp;

    // seconds to wait after each request
    unsigned int wait = 1;

    // timeout in (seconds, useconds)
    // initial value relevant only for the first packet
    // then it is updated to 2*RTT //todo
    struct timeval recv_timeout = {1, 0};

    RTT_time rtt_time = {0.0,0.0,0.0,0.0};
    int seq_num = 0;
    if (argc < 2 || argc > 2) {
        print_usage();
        exit(1);
    }
    ICMP_ID = getpid() & 0xffff;
    host = argv[1];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_RAW;

    // gethostbyname is simpler but does not work well with IPv6
    if ((ret = getaddrinfo(host, NULL, &hints, &servinfo)) != 0) {
        fprintf(stderr, "client: getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
//    printf("socket, ai soctype %d %d", SOCK_RAW, hints.ai_socktype);
        if ((sockfd = socket(p->ai_family, SOCK_RAW, IPPROTO_ICMP)) == -1) {
            perror("client: socket\n");
            continue;
        }

        // set timeout for recvfrom
        status = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recv_timeout, sizeof recv_timeout);
        if (status != 0) {
            perror("client: socket: set recv timeout\n");
            continue;
        }
        // copy to be able to free servinfo
        whereto = *p->ai_addr;
        whereto_len = p->ai_addrlen;
        break;
    }
    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        exit(1);
    }

    printf("myPING %s (%s):\n", host, inet_ntoa(((struct sockaddr_in *) &whereto)->sin_addr));
    seq_num = 0;
    for(;;) {
        struct icmp *icmp_header;
        struct ip   *ip_header;

        // seq num can overflow but it is not that critical and we can hope it just wraps around
        // could do modulo arithmetic but thought it would be an overkill
        compose_packet(packet, seq_num++);
        status = sendto(sockfd, packet, 16, 0, &whereto, whereto_len);//todo fix hardcoded 16
        if (status == -1) {
            printf("unable to send to %s\n", inet_ntoa(((struct sockaddr_in *) &whereto)->sin_addr));
            sleep(wait);
            continue;
        }

        status = recvfrom(sockfd, packet, sizeof(packet), 0, &wherefrom, &wherefrom_len);
        ip_header = (struct ip*)packet;
        icmp_header = (struct icmp*)(packet + sizeof(struct ip));

        if (status != -1 && icmp_header->icmp_id == ICMP_ID) {
            printf("received icmp packet of %d bytes from %s, icmp_seq=%u \n", status,
                   inet_ntoa(((struct sockaddr_in *) &wherefrom)->sin_addr), icmp_header->icmp_seq);
        } else {
            fprintf(stderr, "Request timeout for icmp_seq %u\n", seq_num);
        }
        sleep(wait);

    }


}


void compose_packet(char *packet, u_short seq_num) {
    char *message = "HAHAHAH";
    // struct icmp is much larger and contains more than just the header
    // but all we need is icmp header and first 8 bytes in the struct correspond to this
    struct icmp *icmp_header = (struct icmp *) packet;
    char *time_val = packet + 8;
    int i;
    for (i = 0; i < 8; i++) {
        time_val[i] = message[i];
    }

    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_cksum = 0;
    icmp_header->icmp_seq = seq_num;
    icmp_header->icmp_id = ICMP_ID;        /* PID */
    icmp_header->icmp_cksum = icmp_checksum(packet, 8 + sizeof(message));
}


// https://tools.ietf.org/html/rfc1071
// Computing the Internet Checksum
// Algorithm described in RFC1071
// Note: the given C implementation has
// a typo:
//  says: sum += * (unsigned short) addr++;
//mustbe: sum += * (unsigned short*) addr++;
u_short icmp_checksum(char *packet, int len) {
    u_short *addr = (u_short *) packet;
    long sum = 0;
    u_short checksum;

    while (len > 1) {
        /*  This is the inner loop */
        sum += *(unsigned short *) addr++;
        len -= 2;
    }

    /*  Add left-over byte, if any */
    if (len > 0)
        sum += *(unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    checksum = ~sum;
    return checksum;
}

void print_usage() {
    fprintf(stderr, "usage: ./ping host\n\n");
}