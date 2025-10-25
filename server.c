#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

SSL_CTX* InitServerCTX(void) {

    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS server context (TLS_server_method)
     * 3. Load CA certificate for client verification
     * 4. Configure SSL_CTX to require client certificate (mutual TLS)
     */

    SSL_CTX *ctx = NULL;
    SSL_METHOD *server_method;

    //step 1 - initialize 
    SSL_library_init(); 
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    //step 2 - create the server method then initialize the ctx + check the ctx for null
    server_method = TLSv1_2_server_method();
    ctx = SSL_CTX_new(server_method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    //step 3 - load the ca certificate
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
        // we add our CA to the trusted CAs !!
        // so the rogue client using an untrusted CA cert will not be accepted bc of this!

    //step 4 - require client cert for mutual tls
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);
        //SSL_VERIFY_PEER to even perform the cert validation 
        //SSL_VERIFY_FAIL_IF_NO_PEER_CERT to abort if client doesnt send certificate
        //NULL to use default openssl verif logic
    SSL_CTX_set_verify_depth(ctx, 1);  // look into that one, should it be 0 or 1???
    return ctx;

}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {

     //load the servers cert
     if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM)<=0)
    {       //SSL_FILETYPE_PEM ---> base64 txt & starts with -----BEGIN CERTIFICATE-----
        ERR_print_errors_fp(stderr);
        abort();
    } 

    //load the server's priv key
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM)<=0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    } 

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "the private key does not match the public certificate\n");
        abort();
    } // check server's priv key matches the cert
}

void ShowCerts(SSL* ssl) {

    X509 *cert;
    char *temp;

    // retrieve cert that client sent during handshake
    cert = SSL_get_peer_certificate(ssl);
    if (cert!=NULL)
    {
        printf("Server certificates:\n");
        temp = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", temp); // the one the cert is for
        free(temp);
        temp = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", temp); // the one who signed the cert
        free(temp);
        X509_free(cert);
    }
    else
        printf("no certificates were sent by client.\n");
}

void Servlet(SSL* ssl) { //handles connection after handshake
    /* this one is responsible for the entire communication once the secure channel
    has been established.. ssl_accept()/read()/write()... */

    char buf[1024] = {0}; // init the buffer that stores messages from client for reading

    if (SSL_accept(ssl) == FAIL) // --> HANDSHAAAKE PART (must fail for rogue here)
     {
        printf("peer did not return a certificate or returned an invalid one\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    //server response
    const char* ServerResponse="</Body>\n<Name>cyberAsfalites.com</Name>\n<year>1.5</year>\n<BlogType>Embedded and c/c++</BlogType>\n<Author>Rafaelito Gravaloukos<Author>\n</Body>";
    
    //the CORRECT FORMAT the client should send their message in!!
    const char *cpValidMessage = "<Body><UserName>cyberAsfalites</UserName><Password>69420</Password></Body>";

    ShowCerts(ssl); 

    int bytes = SSL_read(ssl, buf, sizeof(buf)); //server waits to receive from client
    if (bytes <= 0) {
        SSL_free(ssl);
        return;
    }
    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);


    // we match here the client's message to the required format
    /* a bit questionable due to how strcmp() compares literally,
    we just have to makesure not to leave any whitespaces during usr&paswd inputs*/
    if(strcmp(cpValidMessage,buf) == 0){
    SSL_write(ssl, ServerResponse, strlen(ServerResponse)); 
    }
    else{
    SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); 
    }
        
    
    int sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);
    SSL_CTX *ctx;

    ctx = InitServerCTX(); //initialize ssl ctx
    LoadCertificates(ctx, "server.crt", "server.key"); //load server crt and key

    int server = OpenListener(port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        ssl = SSL_new(ctx);  // make a new ssl state w context  
        SSL_set_fd(ssl, client);  // link ssl object to client's socket fd
        Servlet(ssl); // secure channel has been set up, passing it to Servlet to use it
    }

    close(server);
    SSL_CTX_free(ctx);
}
