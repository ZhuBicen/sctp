#include "../unpd.hpp"
#include <iostream>
#include <stdlib.h>


int main(int argc, char* argv[])
{
    if(argc < 2){
        std::cout << "Missing host argument - use " << argv[0] << " host" << std::endl;
        return -1;
    }

    int sock_fd = unpd::socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if(sock_fd == -1){
        std::cerr << "socket error: " << unpd::getErrorString() << std::endl;
        return -1;
    }
    
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));

    
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(unpd::SERVER_PORT);
    inet_pton(AF_INET, argv[1], &servaddr.sin_addr);

    struct sctp_event_subscribe evnts;
    bzero(&evnts, sizeof(evnts));
    evnts.sctp_data_io_event = 1;
    setsockopt(sock_fd,IPPROTO_SCTP, SCTP_EVENTS,
           &evnts, sizeof(evnts));

    std::string line;
    while(getline(std::cin, line)){
        struct sctp_sndrcvinfo sri;
        if (line.length() <= 2 || line[0] != '[') {
            std::cout << "Error, line must be of the form '[streamnum]text, eg: [0]Hello" << std::endl;
            line = "";
            continue;
        }
        sri.sinfo_stream = strtol(&(line.c_str()[1]),NULL,0);
        int send_sz = unpd::sctp_sendmsg(sock_fd, line.c_str(), line.length(),
                                         (struct sockaddr*)&servaddr, sizeof(servaddr),
                                         0, 0, 
                                         sri.sinfo_stream,
                                         0, 0);
        if (send_sz == -1){
            std::cerr << "sctp_sendmsg err:" << unpd::getErrorString();
            return -1;
        }
        struct sockaddr_in peeraddr;
        socklen_t len = sizeof(peeraddr);
        
        char recvbuffer[128];
        int msg_flags = 0;
        
        int read_sz = unpd::sctp_recvmsg(sock_fd, recvbuffer,
                                         sizeof(recvbuffer),
                                         (struct sockaddr*)&peeraddr, &len,
                                         &sri, &msg_flags);
        if (read_sz == -1){
            std::cerr << "sctp_recvmsg err:" << unpd::getErrorString();
            return -1;
        }

        std::cout << "From stream = " << sri.sinfo_stream
                  << " seq = " << sri.sinfo_ssn
                  << " assoc_id = " << sri.sinfo_assoc_id
                  << recv;
    }
    
    line = "";
    return 0;
}



