#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32) /* Put win32 includes here */
#ifndef WINVER
//Windows XP
#define WINVER 0x0501
#endif
#include <winsock2.h>

#include <windows.h>
#include <ws2tcpip.h>

#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

typedef SOCKET socket_type;
#else // Linux includes
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int socket_type;
#endif

#include <cassert>
#include <cerrno>
#include <cstdio>

#include <vector>


struct FileDesc {
};


struct FakeNet {
    static int const min_fd = 1024;

    FakeNet()
        : initialised(true)
    { }


    socket_type socket()
    {
        int fd = min_fd + fds.size();
        fds.push_back(FileDesc());
        return fd;
    }


    std::vector<FileDesc> fds;
    bool initialised;
};


static FakeNet fakenet;


int listen(int sockfd, int backlog)
{
    assert(fakenet.initialised);
    //printf("listen(%d, %d)\n", sockfd, backlog);
    errno = EINVAL;
    return -1;
}


int bind(int sockfd, const struct sockaddr *addr,
         socklen_t addrlen)
{
    assert(fakenet.initialised);
    //printf("bind(%d, %p, %d)\n", sockfd, addr, addrlen);
    errno = EINVAL;
    return 0;
}


socket_type socket(int domain, int type, int protocol)
{
    assert(fakenet.initialised);
    //printf("socket(%d, %d, %d)\n", domain, type, protocol);
    errno = EINVAL;
    return fakenet.socket();
}


int fcntl(int fd, int cmd, ...)
{
    assert(fakenet.initialised);
    //printf("fcntl(%d, %d)\n", fd, cmd);
    errno = EINVAL;
    return 0;
}


int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen)
{
    assert(fakenet.initialised);
    //printf("getsockopt(%d, %d, %d, %p, %p)\n", sockfd, level, optname, optval, optlen);
    errno = EINVAL;
    return 0;
}


int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    assert(fakenet.initialised);
    //printf("setsockopt(%d, %d, %d, %p, %d)\n", sockfd, level, optname, optval, optlen);
    return 0;
}


ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    assert(fakenet.initialised);
    //printf("sendto(%d, %p, %zd, %d, %p, %d)\n", sockfd, buf, len, flags, dest_addr, addrlen);
    errno = EINVAL;
    return 0;
}


ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    assert(fakenet.initialised);
    //printf("recvfrom(%d, %p, %zd, %d, %p, %p)\n", sockfd, buf, len, flags, src_addr, addrlen);
    errno = EINVAL;
    return 0;
}


int usleep(useconds_t usec)
{
    //printf("usleep(%d)\n", usec);
    errno = EINVAL;
    return 0;
}


int close(int fd)
{
    //printf("close(%d)\n", fd);
    errno = EINVAL;
    return 0;
}
