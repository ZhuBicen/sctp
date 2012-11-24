#include "../unpd.hpp"
#include <iostream>
#include <stdlib.h>

int
main(int argc, char **argv)
{
    std::cout << "Server is started" << std::endl;
    
	int stream_increment  = 0;

	if (argc == 2)
		stream_increment = atoi(argv[1]);
 
    // create the socket 
    int sock_fd = unpd::socket(PF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);

    int timeout = 30;
    unpd::setsockopt(sock_fd, IPPROTO_SCTP, SCTP_AUTOCLOSE, &timeout, sizeof(timeout));

    // bind the socket 
    struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(unpd::SERVER_PORT);
    unpd::bind(sock_fd, (__CONST_SOCKADDR_ARG) &servaddr, sizeof(servaddr));
	
    // register sctp event
	struct sctp_event_subscribe evnts;
	bzero(&evnts, sizeof(evnts));
	evnts.sctp_data_io_event = 1;
	evnts.sctp_association_event = 1;
	evnts.sctp_address_event = 1;
	evnts.sctp_send_failure_event = 1;
	evnts.sctp_peer_error_event = 1;
	evnts.sctp_shutdown_event = 1;
	evnts.sctp_partial_delivery_event = 1;
	//evnts.sctp_adaption_layer_event = 1;

    setsockopt(sock_fd, IPPROTO_SCTP, SCTP_EVENTS,
		   &evnts, sizeof(evnts));

    // listen the socket
    unpd::listen(sock_fd, 1024/*LISTENQ*/);

    
	for ( ; ; ) {

        struct sockaddr_in cliaddr;
        struct sctp_sndrcvinfo sri;
        socklen_t len;
		len = sizeof(struct sockaddr_in);
        size_t rd_sz;
        // prepare the read buffer
        char readbuf[1024];
		bzero(readbuf, sizeof(readbuf));
        // message flags
        int msg_flags = 0;

        // receive messages
		rd_sz = unpd::sctp_recvmsg(sock_fd, readbuf, sizeof(readbuf),
                                   (struct sockaddr*)&cliaddr, &len,
                                   &sri,&msg_flags);
        std::cout << "IP = " << unpd::getTextFormIp(cliaddr.sin_addr.s_addr)
                  << ", PORT = " <<  cliaddr.sin_port
                  << ", SID = " << sri.sinfo_stream 
                  << ", AssocationId = " << sri.sinfo_assoc_id
                  << ", MSG = " << readbuf << std::endl;

        if (msg_flags & MSG_NOTIFICATION) {
            unpd::print_notification(readbuf);
            continue;
        } 
        
		if(stream_increment) {
            sri.sinfo_stream++;
            if(sri.sinfo_stream >= unpd::sctp_get_no_strms(sock_fd,(struct sockaddr*)&cliaddr, len)) 
                sri.sinfo_stream = 0;
		}
        // send back the message
        int ret = unpd::sctp_sendmsg(sock_fd, readbuf, rd_sz, 
                                     (struct sockaddr *)&cliaddr, len,
                                     sri.sinfo_ppid,
                                     (sri.sinfo_flags),
                                     sri.sinfo_stream,
                                     0, 0);
        if ( ret == -1){
            std::cout << "Send message size = " << ret << " err = " << unpd::getErrorString() << std::endl;
            exit(-1);
        }
        
	}
}
