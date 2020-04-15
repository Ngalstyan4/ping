#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h> // for close(sockfd)
#include <netdb.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
//
//struct icmp_ping {
//    u_char	icmp_type;		/* type of message, see below */
//    u_char	icmp_code;		/* type sub code */
//    u_short	icmp_cksum;		/* ones complement cksum of struct */
//    n_short	icmp_id;
//    n_short	icmp_seq;
//};

void compose_packet(char *packet);

u_short checksum(char *packet, int len);


int main() {
    char packet[16];
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr whereto;
    socklen_t whereto_len;
    int status;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_RAW;

    char *server_ip = "google.com";
    int ret, sockfd;
    struct icmp *icmp;

    // gethostbyname is simpler but does not work well with IPv6
    if ((ret = getaddrinfo(server_ip, NULL, &hints, &servinfo)) != 0) {
        fprintf(stderr, "client: getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
//    printf("socket, ai soctype %d %d", SOCK_RAW, hints.ai_socktype);
        //    if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))== -1)
        if ((sockfd = socket(p->ai_family, SOCK_RAW, IPPROTO_ICMP)) == -1) {
            perror("client: socket");
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

    compose_packet(packet);
    status = sendto(sockfd, packet, sizeof(packet), 0, &whereto, whereto_len);
    printf("successfylly sent %d bytes to %s\n", status, inet_ntoa(((struct sockaddr_in *) &whereto)->sin_addr));
    status = recvfrom(sockfd, packet, sizeof(packet), 0, &whereto, &whereto_len);
    printf("successfylly recv %d bytes\n", status);


}


void compose_packet(char *packet) {
    char *message = "HAHAHAH";
    struct icmp *icmp_header = (struct icmp *) packet;// todo use custom type here
    char *time_val = packet + 8;
    int i;
    for (i = 0; i < 8; i++) {
        time_val[i] = message[i];
    }

    icmp_header->icmp_type = ICMP_ECHO;
    icmp_header->icmp_code = 0;
    icmp_header->icmp_cksum = 0;
    icmp_header->icmp_seq = 42; //ntransmitted++;
    icmp_header->icmp_id = 44;        /* ID */

    icmp_header->icmp_cksum = checksum(packet, sizeof(icmp_header) + sizeof(message));
}


// https://tools.ietf.org/html/rfc1071
// Computing the Internet Checksum
// Algorithm described in RFC1071
// Note: the given C implementation has
// a typo:
//  says: sum += * (unsigned short) addr++;
//mustbe: sum += * (unsigned short*) addr++;
u_short checksum(char *packet, int len) {
    int count = len;//todo just use len
    u_short *addr = (u_short *) packet;
    long sum = 0;
    u_short checksum;

    while (count > 1) {
        /*  This is the inner loop */
        sum += *(unsigned short *) addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0)
        sum += *(unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    checksum = ~sum;
    return checksum;
}
