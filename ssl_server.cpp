//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    
    //SSL_read
    string challenge="";
    
    int buff_len = 0; 
    char buff[BUFFER_SIZE]; 
    char buffer_chall[20];
    memset(buff,0,sizeof(buff)); 
    buff_len = SSL_read(ssl,buff,BUFFER_SIZE);
    memcpy(buffer_chall, buff, sizeof(buffer_chall)); 

	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", buff2hex((const unsigned char*)buffer_chall, sizeof(buffer_chall)).c_str());

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");
        BIO *bin; 
	BIO* hash; 
	
	char mdbuf[EVP_MAX_MD_SIZE];
	//BIO_new(BIO_s_mem());
        bin = BIO_new(BIO_s_mem()); 
	//BIO_write
        int x = BIO_write(bin, buff, buff_len); 

	//BIO_new(BIO_f_md());
	hash = BIO_new(BIO_f_md()); 
	//BIO_set_md;
	BIO_set_md(hash, EVP_sha1()); 
	//BIO_push;
	BIO_push(hash, bin); //we chain together the the hash and bin here
	//BIO_gets;
	int mdlen=0;
	mdlen = BIO_gets(hash, mdbuf, EVP_MAX_MD_SIZE); // place the data that was in the chained hash to mdbuf 
	//cout << endl << mdlen << endl;
	string hash_string = buff2hex((const unsigned char*)mdbuf, mdlen);
	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash_string.c_str(), mdlen);

	//BIO_free_all(bin);
	BIO_free_all(hash);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"

	printf("4. Signing the key...");

	BIO *prv;

	RSA* rsa;
	unsigned char buff_dump[128]; //make a buffer to dump the encryt into 
	memset(buff_dump, 0, sizeof(buff_dump)); // if there is unused space in the buffer it is set to 0
	
	char myprivfile[] = "rsaprivatekey.pem";
	prv = BIO_new_file(myprivfile, "r"); // this will open the rsaprivatekey.pem file for reading 

    //PEM_read_bio_RSAPrivateKey
	rsa = PEM_read_bio_RSAPrivateKey(prv, NULL, NULL, NULL); //Make the rsa object used for encrypting 
	int size = RSA_size(rsa); 

    //RSA_private_encrypt
        int siglen=0;
	siglen = RSA_private_encrypt(size-11, (const unsigned char*)mdbuf, buff_dump, rsa, RSA_PKCS1_PADDING); // encrypt the key and make it ready to send to the suer.
	if(siglen == -1){print_errors();}

    char* signature= (char*)buff_dump;

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the( client for authentication
	printf("5. Sending signature to client for authentication...");

	//BIO_flush
        int flush = BIO_flush(bin); 
	if(flush == -1){print_errors();} //A check to see if the flush failed
	//SSL_write
    int sig_len = 0;
    char sig_buf[BUFFER_SIZE]; // make a empty buffer to hold the signed hash 
    memset(sig_buf,0, sizeof(sig_buf));
    memcpy(sig_buf, signature, sizeof(sig_buf)); //copy the data in the signature into our newly created buffer
    sig_len = SSL_write(ssl, sig_buf, BUFFER_SIZE); // send the signature to the client for authentification
   if(sig_len <= 0) {print_errors();} // make sure that the server sent the signature right 
    printf("DONE.\n");
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");

    //SSL_read
    int file_len = 0;
    char file[BUFFER_SIZE];
    memset(file,0,sizeof(file)); // preset the data in the receving buffer to 0's 
    file_len = SSL_read(ssl,file,BUFFER_SIZE); // read the users requested data file name
    string file_nm = file; 

    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	//BIO_flush;
	BIO*bfile; 
	
    	char buffer[BUFFER_SIZE];
	memset(buffer,0, sizeof(buffer));
        int srvflsh = BIO_flush(server);
	int bytesRead = 1;
        int bytesSent=0;
	int count = 0;   
        if(srvflsh <= 0){cout << "flushed failed" << endl;}
	//BIO_new_file
	//so here you want find and try to open the file the client wanted
	bfile = BIO_new_file(file_nm.c_str(), "r");
	string fld =  "file not found\0"; 
	if(bfile == NULL) // the file the client wanted is not found the BIO*file will be NULL is thats the case then send a "FNF" message to the client
	{
        SSL_write(ssl, fld.c_str(), fld.size());
	cout << "client's requested file not found " << endl;
	} 
	else // if the file is found then we send the files information to the client where it will be put into a file and output to the terminal for them
	{
	  int temp = 0;
	  while( bytesRead > 0)
	  {
	//BIO_flush(bfile);
	   //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
      	//SSL_write(ssl, buffer, bytesRead);
		bytesRead = BIO_read(bfile, buffer, BUFFER_SIZE); // read the contents from the file into our buffer
	        bytesSent += bytesRead;  
		if(bytesRead < BUFFER_SIZE) // if the buffer is reading the last part of the file then this will execute 
		{
	      	  char temp_buff[bytesRead]; // transfer the contents in the buffer the we are using into a temp buffer 
		  for(int i = 0; i< bytesRead; i++)
	     	  {
			temp_buff[i] = buffer[i];
	  		//cout << i << endl;
		  } 
		  fld = temp_buff;
	  	  fld = fld.substr(0, fld.length());

		  int i = SSL_write(ssl, fld.c_str(), bytesRead); // then send the temp buff to the user. This is to ensure that there is no junk in the current buffer we are using. temp_buff is clean of any junk
;
		  break; 
		}
		else{ // if the size of the data we are sending is BUFFER_SIZE then send it straight to the client
		fld = buffer; 
		SSL_write(ssl, fld.c_str(), bytesRead);
	        //BIO_flush(bfile);
		}
 
	}

	}

    
    printf("SENT.\n");
    printf("    (Bytes sent: %d)\n", bytesSent);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	//SSL_shutdown
	int done = SSL_shutdown(ssl); // Close the SSL connection and reset our server BIO object. 
    //BIO_reset
    int bio_done = BIO_reset(server);
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}

