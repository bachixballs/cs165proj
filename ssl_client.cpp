//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries
#include <openssl/rand.h>
#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");
	print_errors(); 
    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    unsigned char rand_buf[BUFFER_SIZE];
    int rand = RAND_bytes(rand_buf, BUFFER_SIZE);

    string randomNumber="31337";
	//SSL_write
    int buffr_len = 0;
    char buffr[BUFFER_SIZE];
    memset(buffr,0, sizeof(buffr));
    memcpy(buffr, randomNumber.c_str(), sizeof(buffr)); 
    buffr_len = SSL_write(ssl, rand_buf, sizeof(rand_buf)); 
    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", buff2hex((const unsigned char*)rand_buf, 20).c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");

    char read_key[BUFFER_SIZE]; 
    int len=5;
	//SSL_read;
    memset(read_key,0,sizeof(read_key)); // make a buffer to recieve the signed 
    int file_len = SSL_read(ssl,read_key,BUFFER_SIZE); // get the recieved key from the server 
    string key = read_key; 
    printf("RECEIVED.\n");
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)read_key, len).c_str(), len);
    print_errors();
    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");

	//BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free	
	string generated_key="rsapublickey.pem"; 
	string decrypted_key="";
	BIO*bout;
	BIO*pub; 
	RSA* rsa; 
	char mdbuff[BUFFER_SIZE]; 
	bout = BIO_new(BIO_s_mem());  
   	int r = BIO_write(bout, read_key, file_len); 
	pub = BIO_new_file(generated_key.c_str(), "r"); // open the public key so we can use it to set the rsa object to decrypt
	rsa = PEM_read_bio_RSA_PUBKEY(pub, NULL, NULL , NULL); // set the RSA object to decypt the key from the server 
	int nsize = RSA_size(rsa); 
	if((RSA_public_decrypt(nsize, (const unsigned char* )read_key, (unsigned char* )mdbuff, rsa, RSA_PKCS1_PADDING)== -1)){print_errors();} // decrypt the key and output it 
	generated_key = buff2hex((const unsigned char* ) read_key, 20);
        decrypted_key = buff2hex((const unsigned char* ) mdbuff, 20); 
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());
        print_errors();
	int x= BIO_free(pub);
    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	PAUSE(2);
         int chk = BIO_flush(bout); 
	//BIO_flush
        string fname = filename; // this is the name of the file we got from the command line
        fname+='\0';
        //BIO_puts
        int ptd = BIO_puts(bout, fname.c_str());
	
        if(ptd <= 0) {cout << "there was something wronge with the string" << endl;} // if there was a faulty filename this message will be sent to the terminal 
	//SSL_write
    int fnm_len = 0;
    fnm_len = SSL_write(ssl, fname.c_str(), ptd); // send the filenname we want to the server
    //cout << fnm_len << endl;
    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);
print_errors();
    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...\n");

    //BIO_new_file
    BIO* nw_fl;
    nw_fl = BIO_new_file("recieved.txt", "w"); //this will open a file with the same name that the user requested.
    char read_file[BUFFER_SIZE]; 
    string outme; 
    memset(read_file,0,sizeof(read_file));
    int read_len = 1;
    int readme = 1;  
    //SSL_read
	while(1) // this loop while keep reading data from the ssl obejct and put it into the BIO
	{
	 read_len = SSL_read(ssl,read_file,BUFFER_SIZE);
	
	 if(read_len < BUFFER_SIZE) // again this is to make sure that if there is junk in the current buffer to make sure we clean them out and write it cleanly to the file and output it to the terminal 
	  {
	   char temp_buffer[read_len]; 
	   for(int i = 0; i < read_len; i++)
		{
		  temp_buffer[i] = read_file[i]; 
		}
	   readme = BIO_write(nw_fl, read_file, read_len); 
	   for(int i = 0; i < readme; i++)
	    {
		printf("%c", read_file[i]); 
	    }  
	   break;
	  } 
	 else{
	  readme = BIO_write(nw_fl, read_file, read_len);  
	   for(int i = 0; i < readme; i++)
	    {
		printf("%c", read_file[i]); 
	    }	
	 }
	//BIO_write
	//BIO_free
       }
	BIO_free(nw_fl);
	printf("FILE RECEIVED.\n");
print_errors();
    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//SSL_shutdown
	int done = SSL_shutdown(ssl); 
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
print_errors();
    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
