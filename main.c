#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/net_tstamp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <time.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <net/if.h>

#define PRINTERR() fprintf(stderr, "%s:L%i: error\n", __FILE__, __LINE__)


/*
socket hardware timestamp -> source BIO (timetsamp onread)
/------\                 /-------------\
|custom| -- BIO_write -> | source/sink |
|      |                 |             |
| code | <- BIO_read  -- |     BIO     |
\------/                 \-------------/

- use recvmsg(..., MSG_PEEK) in the Source BIO
*/
void backtrace_handler(int sig)
{
    void *array[10];
    size_t size;
    size = backtrace(array, 10);
    fprintf(stderr, "Error: signal %d\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}

static int init_socket(const char *host, const char *path)
{
    int port = 443;
    char *string_port = "443";
    struct addrinfo hints;
    struct addrinfo  *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    int errcode = getaddrinfo(host, string_port, &hints, &result);
    if (errcode != 0)
    {
        PRINTERR();
        return -1;
    }

    int sockfd = -1;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            continue;
        }

        int connected = -1;
        connected = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
        if (connected == -1) {
            sockfd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(result);

    return sockfd;
}

struct my_bio_data {
    int sockfd;
};

void init_SSL(void)
{
    SSL_library_init();
    SSL_load_error_strings();
}

int my_bio_write(BIO *bio, const char *buffer, int len)
{
    printf("    inside bio write\n");
    struct my_bio_data *data = (struct my_bio_data *) BIO_get_data(bio);
    int written = write(data->sockfd, buffer, len);
    return written;
}

void check_socket_options(int sockfd) {
    int current_flags;
    socklen_t len = sizeof(current_flags);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &current_flags, &len) == -1) {
        perror("getsockopt failed");
    } else {
        printf("Current SO_TIMESTAMPING flags: 0x%x\n", current_flags);
    }
}

int my_bio_read(BIO *bio, char *buffer, int len)
{
    printf("    inside bio read\n");
    struct my_bio_data *data = (struct my_bio_data *) BIO_get_data(bio);
    check_socket_options(data->sockfd);

    struct msghdr msg;
    struct iovec iov;
    iov.iov_base = buffer;
    iov.iov_len = 2048;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    char control[1024];
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    // we use the MSG_PEEK flag to make possible to read actual data with read()
    int got = recvmsg(data->sockfd, &msg, MSG_PEEK);

    printf("got: %i\n", got);
    if (got > -1)
    {
        struct timespec* ts = NULL;
        struct cmsghdr* cmsg;

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                struct timespec *timestamps = (struct timespec *)CMSG_DATA(cmsg);
                printf("SW timestamp:      %ld.%09ld\n", timestamps[0].tv_sec, timestamps[0].tv_nsec);
                printf("HW timestamp:      %ld.%09ld\n", timestamps[2].tv_sec, timestamps[2].tv_nsec);
            } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPNS) {
                struct timespec *timestamps_ns = (struct timespec *)CMSG_DATA(cmsg);
                printf("SW timestamp (ns): %ld.%09ld\n", timestamps_ns[0].tv_sec, timestamps_ns[0].tv_nsec);
                printf("HW timestamp (ns): %ld.%09ld\n", timestamps_ns[2].tv_sec, timestamps_ns[2].tv_nsec);
            }
        }

    } else {
        printf("errno: %i\n", errno);
    }

    int response_len = read(data->sockfd, buffer, len);
    //printf("red buffer: %s\n", buffer);
    return response_len;
}

BIO_METHOD *BIO_my_bio_new(void)
{
    BIO_METHOD *_my_bio_method;
    _my_bio_method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "BIO timestamping");

    BIO_meth_set_read(_my_bio_method, my_bio_read);
    BIO_meth_set_write(_my_bio_method, my_bio_write);

    return _my_bio_method;
}

void BIO_my_bio_free(BIO_METHOD *my_bio_method)
{
    if (my_bio_method)
    {
        BIO_meth_free(my_bio_method);
    }
    my_bio_method = NULL;
}

int enable_hw_timestamping(int sockfd, const char *interface_name) {
    struct ifreq ifr;
    struct hwtstamp_config hwconfig;

    memset(&ifr, 0, sizeof(ifr));
    memset(&hwconfig, 0, sizeof(hwconfig));

    // Set the interface name
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    // Set the hardware timestamping config
    hwconfig.tx_type = HWTSTAMP_TX_ON;
    hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

    ifr.ifr_data = (void *)&hwconfig;

    // Apply the configuration
    if (ioctl(sockfd, SIOCSHWTSTAMP, &ifr) < 0) {
        perror("ioctl SIOCSHWTSTAMP failed");
        return -1;
    }

    return 0;
}

int main()
{
    printf("Openssl Version: %s\n", OpenSSL_version(OPENSSL_VERSION));

    signal(SIGSEGV, backtrace_handler);

    //char *host = "echo.free.beeceptor.com";
    char *host = "google.com";
    char *path = "/";
    int sockfd = init_socket(host, path);

    // enable timestamp
    enable_hw_timestamping(sockfd, "wlp3s0"); // operation not permitted on my laptop

    int flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE |
                 SOF_TIMESTAMPING_SYS_HARDWARE | SOF_TIMESTAMPING_SOFTWARE;
    int r = setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));
    int rns = setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPNS, &flags, sizeof(flags));

    // Initialize SSL library
    init_SSL();

    // Initialize SSL context
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        PRINTERR();
        return -1;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    // NOTE: assuming Ubuntu
    if (SSL_CTX_load_verify_locations(ssl_ctx, "/etc/ssl/certs/ca-certificates.crt", NULL) != 1) {
        PRINTERR();
        return -1;
    }

    // Connect SSL over the socket
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_tlsext_host_name(ssl, host);

    SSL_set_fd(ssl, sockfd);
    int ret = SSL_connect(ssl);
    if (ret != 1) {
        PRINTERR();
        int ssl_err_reason = SSL_get_error(ssl, ret);
        printf("err reason: %d\n", ssl_err_reason);
        switch (ssl_err_reason) {
        case SSL_ERROR_NONE:
            printf("1\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("2\n");
            break;
        case SSL_ERROR_WANT_READ:
            printf("3a\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            printf("3b\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
            printf("4a\n");
            break;
        case SSL_ERROR_WANT_ACCEPT:
            printf("4b\n");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("5\n");
            break;
        case SSL_ERROR_SYSCALL:
            printf("6\n");
            break;
        case SSL_ERROR_SSL:
            printf("7\n");
            break;
        default:
            printf("default\n");
            break;
        }
        char err_msg[1024];
        ERR_error_string_n(ERR_get_error(), err_msg, sizeof(err_msg));
        printf("err msg:\n  %s\n", err_msg);
        printf(" - %30.30s \n", SSL_state_string_long(ssl));
        printf(" - %5.10s \n", SSL_state_string(ssl));
        return -1;
    } else {
        long ret = SSL_get_verify_result(ssl);
        if (ret != X509_V_OK) {
            PRINTERR();
            return -1;
        }
    }

    // Create new BIO and set it
    struct my_bio_data *bio_data = malloc(sizeof(struct my_bio_data));
    BIO *my_bio = BIO_new(BIO_my_bio_new());
    bio_data->sockfd = sockfd;
    BIO_set_data(my_bio, bio_data);
    SSL_set_bio(ssl, my_bio, my_bio);

    char request[1024];
    int request_len;
    char response[1024];
    int response_len;

    request_len = sprintf(request, "GET %s HTTP/1.1\r\n"
                                   "Host: %s\r\n\r\n",
                                   path, host);

    printf("  before write (%i)\n", request_len);
    int written = SSL_write(ssl, request, request_len);
    if (written < 0) {
        PRINTERR();
        return -1;
    }
    printf("  after write\n");
    printf("\n");
    printf("  before read\n");
    response_len = SSL_read(ssl, response, sizeof(response));
    if (response_len < 0) {
        PRINTERR();
        return -1;
    }
    printf("  after read\n");
    printf("\n");
    printf("response from the server [%i]:\n%s\n", response_len, response);
}
