#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr_list[0]);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror("Connection failed");
        abort();
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    
    SSL_CTX *ctx = NULL;
    SSL_METHOD *client_method;

    //step 1 - initialize library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    //step 2 - create the client method then initialize the ctx + check the ctx for null
    client_method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(client_method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    //step 3 - load the ca certificate
    
    if(SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) ==0){
        ERR_print_errors_fp(stderr);
        abort();
    }

    //step 4 - verify cert
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
        //only SSL_VERIFY_PEER needed cause sserver is required to send certif by the protocol
        //NULL to use default openssl verif logic
    SSL_CTX_set_verify_depth(ctx, 1);  // look into whether 0 or 1
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{

     //load the clients cert
     if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM)<=0)
    { //SSL_FILETYPE_PEM is base64 txt with -----BEGIN CERTIFICATE-----
        ERR_print_errors_fp(stderr);
        abort();
    } 

    //load the clients priv key
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM)<=0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    } 

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "the private key does not match the public certificate\n");
        abort();
    } // check clients priv key matches the cert

}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    SSL_CTX *ctx;
    SSL *ssl;
    int server;

    ctx = InitCTX(); //initialize ssl ctx
    LoadCertificates(ctx, "client.crt", "client.key"); //load client crt and key

    server = OpenConnection(hostname, port);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    /* TODO:
     * 1. Secure the keys
     * 2. Ascend from darkness
     * 3. Rain fire
     * 4. Unleash the horde
     * 5. Skewer the winged beast
     * 6. Wield a fist of iron
     * 7. Raise hell
     * 8. Freedom!
     */

     // --1-- establish ssl connection using ssl_connect()
     int result = SSL_connect(ssl);
     //printf("ssl_connect epestrepse %d", result);
     if (result == FAIL){
        ERR_print_errors_fp(stderr);
        close(server);
        SSL_CTX_free(ctx);
        return -1;
    }
    puts("Connected!\n");
    printf("%s encryption\n", SSL_get_cipher(ssl));

    // --2-- prompt user for credentials
    char username[64], password[64];
    puts("ASTERAKI MOUUU!! GEIA SOU!");
    printf("Enter username: ");
    scanf("%63s", username);
    printf("Enter password: ");
    scanf("%63s", password);

    // --3-- build xml msg
    char msg[256];
    snprintf(msg, sizeof(msg),
             "<Body><UserName>%s</UserName><Password>%s</Password></Body>",
             username, password);

        // --4-- send the xml message over ssl
    SSL_write(ssl, msg, strlen(msg));

    // --5-- receive n print server's response
    char buf[1024];
    int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes > 0) {
        buf[bytes] = '\0';
        printf("Server response:\n%s\n", buf);
    } else {
        ERR_print_errors_fp(stderr);
    }

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
