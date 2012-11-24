#ifndef UNPD_HPP
#define UNPD_HPP

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <errno.h>
#include <string.h>
#include <string>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <stdio.h>

namespace unpd{

const int SERVER_PORT = 9877;
    
std::string getErrorString()
{
    const int MAX_ERROR_BUFFER = 128;
    char buffer[MAX_ERROR_BUFFER];
    return std::string(strerror_r(errno, buffer, MAX_ERROR_BUFFER));
}

int socket(int domain, int type, int protocol) __THROW
{
    return ::socket(domain, type, protocol);
}

int bind(int fd, __CONST_SOCKADDR_ARG addr, socklen_t len) __THROW
{
    return ::bind(fd, addr, len);
}

int connect(int fd, __CONST_SOCKADDR_ARG addr, socklen_t len)
{
    return ::connect(fd, addr, len);
}

int close(int fd)
{
    return ::close(fd);
}

int setsockopt(int fd, int level, int optname,
               __const void *optval, socklen_t optlen) __THROW
{
    return ::setsockopt(fd, level, optname, optval, optlen);
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) __THROW
{
    return ::getsockopt(fd, level, optname, optval, optlen);
}

int sctp_recvmsg(int s, void *msg, size_t len, sockaddr *from, socklen_t *fromlen,
                 sctp_sndrcvinfo *sinfo, int *msg_flags)
{
    return ::sctp_recvmsg(s, msg, len, from, fromlen, sinfo, msg_flags);
}

int sctp_sendmsg(int s, const void *msg, size_t len, struct sockaddr *to,
                 socklen_t tolen, uint32_t ppid, uint32_t flags,
                 uint16_t stream_no, uint32_t timetolive, uint32_t context)
{
    return ::sctp_sendmsg(s, msg, len, to, tolen, ppid, flags, stream_no, timetolive, context);
}

int sctp_send(int sd, const void* msg, size_t len, const struct sctp_sndrcvinfo* sinfo, int flags)
{
    return ::sctp_send(sd, msg, len, sinfo, flags);
}

int listen(int s, int backlog) __THROW
{
    return ::listen(s, backlog);
}

int fcntl(int fd, int cmd, int flags)
{
    return ::fcntl(fd, cmd, flags);
}

int select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    return ::select(n, readfds, writefds, exceptfds, timeout);
}

int sctp_opt_info(int sd, sctp_assoc_t id, int opt, void *arg, socklen_t *size)
{
    return ::sctp_opt_info(sd, id, opt, arg, size);
}

int sctp_getpaddrs(int sd, sctp_assoc_t id, struct sockaddr **addrs)
{
    return ::sctp_getpaddrs(sd, id, addrs);
}

int sctp_freepaddrs(struct sockaddr *addrs)
{
    return ::sctp_freepaddrs(addrs);
}

int inet_pton(int af, const char *src, void *dst)
{
    return inet_pton(af, src, dst);
}


sctp_assoc_t
sctp_address_to_associd2(int sock_fd, struct sockaddr *sa, socklen_t salen)
{
	struct sctp_paddrinfo sp;
	socklen_t siz;

	siz = sizeof(struct sctp_paddrinfo);
	bzero(&sp,siz);
	memcpy(&sp.spinfo_address, sa, salen);
	int ret = unpd::sctp_opt_info(sock_fd,0,
            SCTP_GET_PEER_ADDR_INFO, &sp, &siz);

	if (ret != 0){
        std::cerr << "sctp_opt_info fatal, ret = " << ret << std::endl;
        exit(1);
	}
	return(sp.spinfo_assoc_id);
}
    

int 
sctp_get_no_strms(int sock_fd,struct sockaddr *to, socklen_t tolen)
{
	socklen_t retsz;
	struct sctp_status status;
	retsz = sizeof(status);	
	bzero(&status,sizeof(status));

	status.sstat_assoc_id = sctp_address_to_associd2(sock_fd,to,tolen);
	//printf("The assocation id = %d\n", status.sstat_assoc_id);
    unpd::getsockopt(sock_fd,IPPROTO_SCTP, SCTP_STATUS,
		   &status, &retsz);
	return(status.sstat_outstrms);
}

std::string getTextFormIp(u_long ip)
{
    std::ostringstream oss;
    char buffer[256];
    oss << inet_ntop(AF_INET, &ip, buffer, 256);
    return oss.str();
}
void
print_notification(char *notify_buf)
{
	union sctp_notification *snp;
	struct sctp_assoc_change *sac;
	struct sctp_paddr_change *spc;
	struct sctp_remote_error *sre;
	struct sctp_send_failed *ssf;
	struct sctp_shutdown_event *sse;
	struct sctp_adaption_event *ae;
	struct sctp_pdapi_event *pdapi;
	const char *str;

	snp = (union sctp_notification *)notify_buf;
	switch(snp->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		sac = &snp->sn_assoc_change;
		switch(sac->sac_state) {
		case SCTP_COMM_UP:
			str = "COMMUNICATION UP";
			break;
		case SCTP_COMM_LOST:
			str = "COMMUNICATION LOST";
			break;
		case SCTP_RESTART:
			str = "RESTART";
			break;
		case SCTP_SHUTDOWN_COMP:
			str = "SHUTDOWN COMPLETE";
			break;
		case SCTP_CANT_STR_ASSOC:
			str = "CAN'T START ASSOC";
			break;
		default:
			str = "UNKNOWN";
			break;
		} /* end switch(sac->sac_state) */
		printf("SCTP_ASSOC_CHANGE: %s, assoc=0x%x\n", str,
		       (uint32_t)sac->sac_assoc_id);
		break;
	case SCTP_PEER_ADDR_CHANGE:
		spc = &snp->sn_paddr_change;
		switch(spc->spc_state) {
		case SCTP_ADDR_AVAILABLE:
			str = "ADDRESS AVAILABLE";
			break;
		case SCTP_ADDR_UNREACHABLE:
			str = "ADDRESS UNREACHABLE";
			break;
		case SCTP_ADDR_REMOVED:
			str = "ADDRESS REMOVED";
			break;
		case SCTP_ADDR_ADDED:
			str = "ADDRESS ADDED";
			break;
		case SCTP_ADDR_MADE_PRIM:
			str = "ADDRESS MADE PRIMARY";
			break;
		default:
			str = "UNKNOWN";
			break;
		} /* end switch(spc->spc_state) */
        std::cout <<"SCTP_PEER_ADDR_CHANGE: " << str << std::endl;
		// printf("SCTP_PEER_ADDR_CHANGE: %s, addr=%s, assoc=0x%x\n", str,
		//        sock_ntop((sockaddr *)&spc->spc_aaddr, sizeof(spc->spc_aaddr)),
		//        (uint32_t)spc->spc_assoc_id);
		break;
	case SCTP_REMOTE_ERROR:
		sre = &snp->sn_remote_error;
		printf("SCTP_REMOTE_ERROR: assoc=0x%x error=%d\n",
		       (uint32_t)sre->sre_assoc_id, sre->sre_error);
		break;
	case SCTP_SEND_FAILED:
		ssf = &snp->sn_send_failed;
		printf("SCTP_SEND_FAILED: assoc=0x%x error=%d\n",
		       (uint32_t)ssf->ssf_assoc_id, ssf->ssf_error);
		break;
	// case SCTP_ADAPTION_INDICATION:
	// 	ae = &snp->sn_adaption_event;
	// 	printf("SCTP_ADAPTION_INDICATION: 0x%x\n",
	// 	    (u_int)ae->sai_adaption_ind);
	// 	break;
	case SCTP_PARTIAL_DELIVERY_EVENT:
	    pdapi = &snp->sn_pdapi_event;
	    if(pdapi->pdapi_indication == SCTP_PARTIAL_DELIVERY_ABORTED)
		    printf("SCTP_PARTIAL_DELIEVERY_ABORTED\n");
	    else
		    printf("Unknown SCTP_PARTIAL_DELIVERY_EVENT 0x%x\n",
			   pdapi->pdapi_indication);
	    break;
	case SCTP_SHUTDOWN_EVENT:
		sse = &snp->sn_shutdown_event;
		printf("SCTP_SHUTDOWN_EVENT: assoc=0x%x\n",
		       (uint32_t)sse->sse_assoc_id);
		break;
	default:
		printf("Unknown notification event type=0x%x\n", 
		       snp->sn_header.sn_type);
	}
}    

}

#endif
