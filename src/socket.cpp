#include <ext/socket.hpp>
#include <regex>
#include <cassert>

#include <WinSock2.h>
#include <ws2ipdef.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <Windows.h>

namespace std {
    namespace ext {

        struct SocketInitializer
        {
            SocketInitializer()
            {
                WSADATA init;
                ::WSAStartup(MAKEWORD(2, 2), &init);
            }

            ~SocketInitializer() { ::WSACleanup(); }
        };

        SocketInitializer globalInitializer;

        bool is_ipv4(const char * addr) {
            bool rs = false;
            string pattern = { "((([0-9])|([1-9]\\d{1})|([1]\\d{2})|([2][0-4]\\d{1})|([2][5][0-5]))\\.){3}\
                            (([0-9])|([1-9]\\d{1})|([1]\\d{2})|([2][0-4]\\d{1})|([2][5][0-5])):(\\d+)" };
            regex re(pattern);
            rs = regex_match(addr, re);
            return rs;
        }
        size_t find_sep(const char* str) {
            if (!str) return -1;
            size_t len = strlen(str);
            size_t pos = 0;
            while (str[pos] != ':') {
                pos++;
                if (pos == len) {
                    pos = -1;
                    break;
                }
            }
            return pos;
        }
        bool is_loop_back(const char* addr) {
            return !strncmp("localhost", addr, 9);
        }

        ip::ip(const char * str_addr)
            : m_addr(nullptr)
            , m_proto((int8_t)net_proto::inet)
        {
            if (str_addr) {
                if (is_ipv4(str_addr)) {
                    m_addr = (sockaddr_in*)::malloc(sizeof(sockaddr_in));
                    memset(m_addr, 0, sizeof(sockaddr_in));
                    ::inet_pton(AF_INET, str_addr, m_addr);
                }
                else if (is_loop_back(str_addr)) {
                    m_addr = (sockaddr_in*)::malloc(sizeof(sockaddr_in));
                    memset(m_addr, 0, sizeof(sockaddr_in));
                    m_addr->sin_family = AF_INET;
                    m_addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK); //INADDR_ANY
                    size_t sep = find_sep(str_addr);
                    int port = atoi(str_addr + sep + 1);
                    m_addr->sin_port = htons(port);
                }
                else {
                    m_addr6 = (sockaddr_in6*)::malloc(sizeof(sockaddr_in6));
                    memset(m_addr6, 0, sizeof(sockaddr_in6));
                    ::inet_pton(AF_INET6, str_addr, m_addr6);
                    m_proto = (int8_t)net_proto::inet6;
                }
            }
        }
        ip::~ip()
        {
            if (m_addr) {
                ::free(m_addr);
                m_addr = nullptr;
            }
        }
        net_proto ip::get_proto() const
        {
            return (net_proto)m_proto;
        }
        int ip::get_addr_len() const
        {
            switch (get_proto())
            {
            case net_proto::inet:
                return sizeof(sockaddr_in);
            case net_proto::inet6:
                return sizeof(sockaddr_in6);
            }
            return 0;
        }
        socket::socket(socket_type type, net_proto net, ip_proto ip)
            : m_fd(0)
        {
            int pf = PF_INET;
            switch (net) {
            case net_proto::inet:
                pf = PF_INET;
                break;
            case net_proto::inet6:
                pf = PF_INET6;
                break;
            }
            int st = SOCK_STREAM;
            switch (type) {
            case socket_type::stream:
                st = SOCK_STREAM;
                break;
            case socket_type::diagram:
                st = SOCK_DGRAM;
                break;
            }
            int iproto = IPPROTO_TCP;
            switch (ip) {
            case ip_proto::tcp:
                iproto = IPPROTO_TCP;
                break;
            case ip_proto::udp:
                iproto = IPPROTO_UDP;
                break;
            case ip_proto::ipv4:
                iproto = IPPROTO_IPV4;
                break;
            case ip_proto::ipv6:
                iproto = IPPROTO_IPV6;
                break;
            }
            m_fd = ::socket(pf, st, 0);
            assert(m_fd > 0);
        }
        bool socket::is_valid() const
        {
            return m_fd > 0;
        }
        socket::socket(type fd) : m_fd(fd) {}
        socket::~socket()
        {
            if (m_fd > 0) {
                int ret = ::shutdown(m_fd, 0);
                m_fd = 0;
            }
        }
        socket& socket::set_blocking(bool block)
        {
            unsigned long ul = block ? 0 : 1;
            ::ioctlsocket(m_fd, FIONBIO, &ul);
            return *this;
        }
        socket& socket::set_reuse_addr(bool reuse)
        {
            BOOL iReuse = reuse ? TRUE : FALSE;
            ::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&iReuse, sizeof(iReuse));
            return *this;
        }
        socket& socket::set_tcp_no_delay(bool nodelay)
        {
            BOOL iNoDelay = nodelay ? TRUE : FALSE;
            ::setsockopt(m_fd, SOL_SOCKET, TCP_NODELAY, (const char*)&iNoDelay, sizeof(iNoDelay));
            return *this;
        }
        void socket::close()
        {
            int ret = ::closesocket(m_fd);
        }
        int socket::bind(ip const & addr)
        {
            return ::bind(m_fd, (const sockaddr*)addr.get_addr(), addr.get_addr_len());
        }
        int socket::connect(ip const & addr)
        {
            return ::connect(m_fd, (const sockaddr*)addr.get_addr(), addr.get_addr_len());
        }
        int socket::listen(int max_conn)
        {
            // backlog
            return ::listen(m_fd, max_conn);
        }
        int socket::send(const char* buff, int send_len)
        {
            return ::send(m_fd, buff, send_len, 0);
        }
        int socket::recv(char * buff, int recv_len)
        {
            return ::recv(m_fd, buff, recv_len, 0);
        }
        socket* socket::accept()
        {
            type ret = ::accept(m_fd, nullptr, nullptr);
            if (ret < 0) {
                return nullptr;
            }
            else {
                return new socket(ret);
            }
        }
#if HAS_OPENSSL
        ssl_socket::ssl_socket() : socket(), m_ssl(nullptr), m_ssl_ctx(nullptr), m_is_client(false)
        {
            m_ssl = SSL_new(m_ssl_ctx);
            SSL_set_fd(m_ssl, m_fd);
        }
        ssl_socket::ssl_socket(socket::type fd, ssl_st* ssl)
            : socket(fd), m_ssl(ssl), m_ssl_ctx(nullptr) {}

        ssl_socket::~ssl_socket()
        {
            SSL_free(m_ssl);
        }
        int ssl_socket::connect(ip const & addr)
        {
            m_is_client = true;
            int ret = socket::connect(addr);
            if (ret >= 0) {
                ret = SSL_connect(m_ssl);
            }
            return ret;
        }
        int ssl_socket::listen(int max_conn)
        {
            m_is_client = false;
            return socket::listen(max_conn);
        }
        void ssl_socket::close()
        {
            SSL_shutdown(m_ssl);
            socket::close();
        }
        int ssl_socket::send(const char * buff, int send_len)
        {
            return SSL_write(m_ssl, buff, send_len);
        }
        int ssl_socket::recv(char * buff, int recv_len)
        {
            return SSL_read(m_ssl, buff, recv_len);
        }
        socket* ssl_socket::accept()
        {
            socket::type ret = ::accept(m_fd, nullptr, nullptr);
            if (ret < 0) {
                return nullptr;
            }
            else {
                SSL* ssl = SSL_new(m_ssl_ctx);
                SSL_set_fd(ssl, ret);
                if (SSL_accept(ssl) == -1) {
                    SSL_free(ssl);
                    ::closesocket(ret);
                    return nullptr;
                }
                return new ssl_socket(ret, ssl);
            }
        }
#endif
    }
}