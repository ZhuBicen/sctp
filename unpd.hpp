#ifndef UNPD_HPP
#define UNPD_HPP

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <errno.h>
#include <string.h>
#include <string>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iostream>

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

}

#endif
