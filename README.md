Students : Gravalos Georgios 2021030001, Kerimi Rafaela - Aikaterina 2021030007
Assignment 1 - Secure client-server communication using SSL

The project consists of 4 vital parts:
- server.c : The server, which will only accept certificates from our trusted CA
- client.c : The trusted client, whose certificate is signed by the trustedd CA
- rclient.c : the rogue client, whose certificate is signed by an untrusted/rogue CA
- utils (which is the folder where all the certificates are stored)

The point of the assignment is to showcase how the server will normally handshake and establish a secure connection with the trusted client, whereas the rogue client will be
dropped during the handshake, since their certificate isn't signed by a trusted CA.

We issued the certificates as follows:

1) We created the trusted CA certificate and private key:
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt -subj '/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=RootCA'

    each parameter is:
    - openssl req -x509 : initiates the certificate request. the -x509 flag specifies that it should output a self-signed certificate.
    - nodes : for simplicity purposes, it instructs SSL not to encrypt the private key, so that we don't have to type a password every time we start the server.
    - days 365 : the certificate should be valid for one year.
    - newkey rsa:2048  : generates a private key, uses the RSA algorithm with 2048-bit long key.
    - keyout ca.key : "ca.key" will be the output file for the generated key. (however we later moved the file to utils/ca.key)
    - out ca.crt : "ca.crt" will be the output file for the generated certificate. (however we later moved the file to utils/ca.crt)
    - subj '...' : Provides the subject information for the certificate.
                   /C=GR : Country (Greece)
                   /ST=Crete : State/Province (Crete)
                   /L=Chania : Locality/City (Chania)
                   /O=TechnicalUniversityofCrete : Organization (TUC)
                   /OU=ECELab : Organizational Unit
                   /CN=RootCA : Common Name (RootCA is our trusted CA)

2) We requested teh server certificate:
        openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj '/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=localhost'
    
    - openssl req : same as before
    - new : generate new certificate request
    - newkey rsa:2048  : generates the private server key (server.key), uses the RSA algorithm with 2048-bit long key.
    - nodes : don't encrypt the server private key 
    - keyout server.key : "server.key" will be the output file for the generated key. (however we later moved the file to utils/server.key)
    - out server.csr : "server.csr" will be the output file for the certificate signing request. (however we later moved the file to utils/server.csr)
    - subj '...' : Provides the subject information for the request.
                The only difference from above is 
                   /CN=localhost : We're requesting it for the server who runs on localhost (and that's what we intend to do)

Then, we signed the certificate with the trusted CA:
        openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 

    - openssl x509 : use the x509 utility, which manages actual certificates
    - -req -in server.csr : tells the x509 tool that the input file (-in) is a request, not a certificate (server.csr).
    - -CA ca.crt : specifies the CA's certificate
    - -CAkey ca.key : specifies the CA's private key, which is used to do the actual signing
    - CAcreateserial : generates a serial number for the certificate
    - out server.crt : this is where the final, signed server certificate will be saved.
    - days 365 : the server certificate will be valid for one year.
    - sha 256 : use the sha256 hashing algorithm for the signature.
Now this grants us at last, the server certificate.
Same exact process was followed for the client.
