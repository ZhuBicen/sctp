#include "../unpd.hpp"
#include <iostream>
#include <stdlib.h>

int
main(int argc, char **argv)
{
    std::cout << "Server is started" << std::endl;
    
	int sock_fd,msg_flags;
	char readbuf[1024];
	struct sockaddr_in servaddr, cliaddr;
	struct sctp_sndrcvinfo sri;
	struct sctp_event_subscribe evnts;
	int stream_increment=1;
	socklen_t len;
	size_t rd_sz;

	if (argc == 2)
		stream_increment = atoi(argv[1]);
 
    sock_fd = unpd::socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(unpd::SERVER_PORT);

    unpd::bind(sock_fd, (__CONST_SOCKADDR_ARG) &servaddr, sizeof(servaddr));
	
	bzero(&evnts, sizeof(evnts));
	evnts.sctp_data_io_event = 1;
    setsockopt(sock_fd, IPPROTO_SCTP, SCTP_EVENTS,
		   &evnts, sizeof(evnts));

    unpd::listen(sock_fd, 1024/*LISTENQ*/);
	for ( ; ; ) {
		len = sizeof(struct sockaddr_in);
        msg_flags = 0;
		bzero(readbuf, sizeof(readbuf));
		rd_sz = unpd::sctp_recvmsg(sock_fd, readbuf, sizeof(readbuf),
                                   (struct sockaddr*)&cliaddr, &len,
                                   &sri,&msg_flags);
        std::cout << "IP = " << ntohl(cliaddr.sin_addr.s_addr) << ", PORT = " <<  cliaddr.sin_port
                  << ",  SID = " << sri.sinfo_stream << ", MSG = " << readbuf << std::endl;

		if(stream_increment) {
		  sri.sinfo_stream++;
          if(sri.sinfo_stream >= unpd::sctp_get_no_strms(sock_fd,(struct sockaddr*)&cliaddr, len)) 
			sri.sinfo_stream = 0;
		}
        unpd::sctp_sendmsg(sock_fd, readbuf, rd_sz, 
                           (struct sockaddr *)&cliaddr, len,
                           sri.sinfo_ppid,
                           sri.sinfo_flags,
                           sri.sinfo_stream,
                           0, 0);
	}
}
