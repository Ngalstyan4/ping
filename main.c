#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> // for close(sockfd), sleep(t)
#include <netdb.h>
#include <errno.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <signal.h>
#include <math.h>

#define ICMP_HEADER_SIZE 8
#define IP_HEADER_SIZE  20
typedef struct RTT_time {
    //// times in millis
    float min;
    float max;
    float sum;
    float sumsq;
    int cnt;
} RTT_time;

/***************************** DANGER ZONE BEGIN ********************************/
/* These need to be global so the SIGINT signal handler can access them*/

char *host;
int ntransmitted = 0, nreceived = 0;
/* sine we timeout at 1s, 2020ms is more than enough for init min value.*/
RTT_time rtt_time_stats = {.min=2020., .max=0.0, .sum=0.0, .sumsq=0.0, .cnt=0};

u_short ICMP_ID;

/***************************** DANGER ZONE END ********************************/

int init_socket(int ip_ttl, struct timeval *recv_timeout, struct sockaddr *whereto, socklen_t *whereto_len);

int compose_packet(char *packet, u_short seq_num, struct timeval *send_time);

float update_stats(struct RTT_time *rtt_time_stats, struct timeval *recv_time, struct timeval *send_time_in_data);

void exit_with_stats(int sig_num);

u_short icmp_checksum(char *packet, int len);

int icmp_is_valid_reply(char *packet, int seq_num);

void ip_handle_if_timexceed(char *packet, int size);

void parse_args(int argc, char **argv, int *ttl, int *timeout, int *count);

int main(int argc, char **argv) {
    // echo reply:     20(ip header) + 8(ICMP header) + 16(timestamp)
    // time exceeded:  20(ip header) + 8(ICMP header) + 20(orig ip header) + 8 (8 bits of orig data)
    char packet[sizeof(struct ip) + ICMP_HEADER_SIZE + sizeof(struct ip) + ICMP_HEADER_SIZE];

    // for time data in sent and received packets
    struct sockaddr whereto;
    socklen_t whereto_len;
    struct sockaddr wherefrom;
    socklen_t wherefrom_len = sizeof(wherefrom);

    // timeout in (seconds, useconds)
    // initial value relevant only for the first packet
    // then it is updated to 2*RTT
    struct timeval recv_timeout = {1, 0};
    // seconds to wait after each request
    unsigned int interrequest_wait = 1;

    // general var for functions that return int/status
    int status;
    int sockfd;
    int seq_num;

    int ip_ttl = -1;
    int timeout = -1;
    int count = -1;

    parse_args(argc, argv, &ip_ttl, &timeout, &count);

    ICMP_ID = getpid() & 0xffff;
    sockfd = init_socket(ip_ttl, &recv_timeout, &whereto, &whereto_len);

    printf("myPING %s (%s):\n", host, inet_ntoa(((struct sockaddr_in *) &whereto)->sin_addr));
    // handle cmd+c to print stats before exit. Just move along if these error and we are unable to catch the signals
    signal(SIGINT, exit_with_stats);
    signal(SIGALRM, exit_with_stats);
    if (timeout != -1) alarm(timeout);

    seq_num = 0;
    for (;;) {
        struct icmp *icmp_header;
        struct ip *ip_header;
        struct timeval send_time, recv_time;
        int size;

        gettimeofday(&send_time, NULL);

        // seq num can overflow but it is not that critical and we can hope it just wraps around
        // could do modulo arithmetic but thought it would be an overkill
        size = compose_packet(packet, seq_num++, &send_time);
        status = sendto(sockfd, packet, size, 0, &whereto, whereto_len);
        if (status == -1) {
            printf("myping: sendto: unable to send to %s, icmp_seq=%u never sent\n",
                   inet_ntoa(((struct sockaddr_in *) &whereto)->sin_addr), seq_num - 1);
            sleep(interrequest_wait);
            /* looks like regular ping does not continue here and tries to receive the packet with icmp_seq
             * even if it never got sent. I think there is no point of that and so will continue here.
             */
            continue;
        }

        ntransmitted++;
        /* ignore received packets if we have already announced them as lost */
        do {
            status = recvfrom(sockfd, packet, sizeof(packet), 0, &wherefrom, &wherefrom_len);
            // could reuse send_time if desperate for space, but this is clearer
            gettimeofday(&recv_time, NULL);

            ip_handle_if_timexceed(packet, status);

            // packet must be at least 44 bytes. If it is not, there was an error
            if (status < sizeof(struct ip) + ICMP_HEADER_SIZE + sizeof(struct timeval)) continue;
            ip_header = (struct ip *) packet;
            icmp_header = (struct icmp *) (packet + sizeof(struct ip));
            //printf("receiving in header: %u , seq-1: %u", icmp_header->icmp_seq, seq_num-1);
        } while (status != -1 && icmp_is_valid_reply((char *) icmp_header, seq_num) == -1);

        if (status != -1) {
            float rtt;
            struct timeval *send_time_in_data = (struct timeval *) (packet + sizeof(struct ip) + ICMP_HEADER_SIZE);

            nreceived++;
            rtt = update_stats(&rtt_time_stats, &recv_time, send_time_in_data);

            if (rtt_time_stats.cnt == 3) {
                /* improvising here:
                 * Wait some time to accumulate data then update recv_time
                 */
                memset(&recv_timeout, 0, sizeof(recv_timeout));
                // TIMEOUT = 2*RTT
                recv_timeout.tv_usec = 2 * rtt_time_stats.sum * 1000.0 / rtt_time_stats.cnt;
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &recv_timeout, sizeof(recv_timeout));
            }

            printf("received icmp packet of %d bytes from %s, icmp_seq=%u, ttl=%u, time=%.3fms \n", status,
                   inet_ntoa(((struct sockaddr_in *) &wherefrom)->sin_addr), icmp_header->icmp_seq, ip_header->ip_ttl,
                   rtt);
        } else {
            fprintf(stderr, "Request timeout for icmp_seq %u\n", seq_num - 1);
        }

        if (count != -1 && nreceived >= count) exit_with_stats(0);
        sleep(interrequest_wait);
    }
}

/* Initiates a raw socket and returns a valid socket or exits the program with an error message */
int init_socket(int ip_ttl, struct timeval *recv_timeout, struct sockaddr *whereto, socklen_t *whereto_len) {
    int sockfd;
    int status;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_RAW;

    // gethostbyname is simpler but does not work well with IPv6
    if ((status = getaddrinfo(host, NULL, &hints, &servinfo)) != 0) {
        fprintf(stderr, "myping: getaddrinfo: %s\n", gai_strerror(status));
        exit(1);
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, SOCK_RAW, IPPROTO_ICMP)) == -1) {
            if (EPERM == errno) {
                fprintf(stderr, "myping: Operation not permitted\n"
                                "Hint: myping needs to create raw sockets which often require superuser privileges\n"
                                "please re-run the binary with elevated privileges\n"
                                "sudo ./ping\n");
                exit(1);
            }
            perror("myping: socket\n");
            continue;
        }

        if (ip_ttl != -1) {
            status = setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ip_ttl, sizeof(ip_ttl));;
            if (status != 0) {
                perror("myping: socket: set ttl\n");
                continue;
            }
        }
        // set timeout for recvfrom
        status = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) recv_timeout, sizeof(struct timeval));
        if (status != 0) {
            perror("myping: socket: set recv timeout\n");
            continue;
        }
        // copy to be able to free servinfo
        *whereto = *p->ai_addr;
        *whereto_len = p->ai_addrlen;
        break;
    }
    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "myping: failed to connect\n");
        exit(1);
    }
    return sockfd;
}

/* Compose ICMP message in packet and return its size (includes header and data) */
int compose_packet(char *packet, u_short seq_num, struct timeval *send_time) {
    // struct icmp is much larger and contains more than just the header
    // but all we need is icmp header and first 8 bytes in the struct correspond to this
    struct icmp *icmp_header = (struct icmp *) packet;
    struct timeval *time_val = (struct timeval *) (packet + 8);
    *time_val = *send_time;

    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_cksum = 0;
    icmp_header->icmp_seq = seq_num;
    icmp_header->icmp_id = ICMP_ID;        /* PID */
    icmp_header->icmp_cksum = icmp_checksum(packet, ICMP_HEADER_SIZE + sizeof(struct timeval));
    return ICMP_HEADER_SIZE + sizeof(struct timeval);
}

float update_stats(struct RTT_time *rtt_time_stats, struct timeval *recv_time, struct timeval *send_time_in_data) {
    float rtt;
    rtt = recv_time->tv_sec - send_time_in_data->tv_sec;
    rtt *= 1000000;
    // not sure if negative result below is always defined, but works in my environment
    rtt += recv_time->tv_usec - send_time_in_data->tv_usec;
    // back to millis
    rtt /= 1000;
    rtt_time_stats->sum += rtt;
    rtt_time_stats->sumsq += rtt * rtt;
    rtt_time_stats->cnt++;
    if (rtt < rtt_time_stats->min)
        rtt_time_stats->min = rtt;
    if (rtt > rtt_time_stats->max)
        rtt_time_stats->max = rtt;

    return rtt;
}

void exit_with_stats(int sig_num) {
    // Remove signal handlers to make sure the other handler does not call it while we are already here
    signal(SIGINT, SIG_DFL);
    signal(SIGALRM, SIG_DFL);
    printf("\n--- %s myping statistics ---\n", host);
    printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n", ntransmitted, nreceived,
           (ntransmitted - nreceived) * 100.0 / ntransmitted);

    if (nreceived != 0)
        printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n", rtt_time_stats.min,
               rtt_time_stats.sum / rtt_time_stats.cnt,
               rtt_time_stats.max,
               sqrt((rtt_time_stats.sumsq - rtt_time_stats.sum) / rtt_time_stats.cnt));
    exit(0);
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

int icmp_is_valid_reply(char *packet, int seq_num) {
    u_short checksum;
    struct icmp *icmp_header = (struct icmp *) packet;
    if (icmp_header->icmp_type != ICMP_ECHOREPLY) return -1;
    if (icmp_header->icmp_id != ICMP_ID) return -1;
    if (icmp_header->icmp_seq < seq_num - 1) return -1;

    checksum = icmp_header->icmp_cksum;
    icmp_header->icmp_cksum = 0;
    icmp_header->icmp_cksum = icmp_checksum(packet, ICMP_HEADER_SIZE + sizeof(struct timeval));
    if (icmp_header->icmp_cksum != checksum) return -1;

    return 0;
}

void ip_handle_if_timexceed(char *packet, int size) {
    u_short checksum;
    struct ip *ip_header = (struct ip *) packet;
    struct icmp *icmp_header = (struct icmp *) (packet + sizeof(struct ip));

    /* struct icmp is larger than the header it represents hence using a const */
    struct ip *nested_ip_header = (struct ip *) (packet + sizeof(struct ip) + ICMP_HEADER_SIZE);
    struct icmp *nested_icmp_header = (struct icmp *) (packet + sizeof(struct ip) + ICMP_HEADER_SIZE +
                                                       sizeof(struct ip));
    if (size == -1) return;

    checksum = icmp_header->icmp_cksum;
    icmp_header->icmp_cksum = 0;
    icmp_header->icmp_cksum = icmp_checksum((char *) icmp_header, size - sizeof(struct ip));

    /*todo:: after hours of work still could not get the time exceeded message checksum to check out...*/
    if (/* icmp_header->icmp_cksum == checksum && */
            nested_icmp_header->icmp_id == ICMP_ID &&
            icmp_header->icmp_type == ICMP_TIMXCEED &&
            icmp_header->icmp_code == ICMP_TIMXCEED_INTRANS) {
        printf("%d bytes from %s: Time to live exceeded \n", size, inet_ntoa(ip_header->ip_src));
        printf("Src\t\tDst\n");
        // N.B the next two need to be in separate lines since inet_ntoa uses a single static buffer
        printf("%s\t", inet_ntoa(nested_ip_header->ip_src));
        printf("%s\n", inet_ntoa(nested_ip_header->ip_dst));
    }

    icmp_header->icmp_cksum = checksum;
}

static void exit_with_usage() {
    fprintf(stderr, "usage: ./ping [-m TTL] [-t timeout] [-c count] host\n\n");
    exit(1);
}

void parse_args(int argc, char **argv, int *ttl, int *timeout, int *count) {
    int c;
    while ((c = getopt(argc, argv, "m:t:c:")) != -1) {
        switch (c) {
            case 'm':
                *ttl = atoi(optarg);
                if (*ttl <= 0) {
                    fprintf(stderr, "./ping: invalid TTL: `%s'\n", optarg);
                    exit_with_usage();
                }
                break;
            case 't':
                *timeout = atoi(optarg);
                if (*timeout <= 0) {
                    fprintf(stderr, "./ping: invalid timeout: `%s'\n", optarg);
                    exit_with_usage();
                }
                break;
            case 'c':
                *count = atoi(optarg);
                if (*count <= 0) {
                    fprintf(stderr, "./ping: invalid count: `%s'\n", optarg);
                    exit_with_usage();
                }
                break;
            default:
                exit_with_usage();
                break;
        }
    }
    if (optind != argc - 1) exit_with_usage();
    host = argv[optind];
}