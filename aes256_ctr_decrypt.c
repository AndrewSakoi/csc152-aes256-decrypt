//Andrew Sakoi
//Decrypt in OPEN_SSL API
//Homework 3
//CSC 152
//compile with -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h> //Open SSL API
#define BUF_LEN 1024


int hex_to_bytes(unsigned char result[], const char hex[], unsigned int hex_len) {
    unsigned int i;
    if (hex_len % 2 == 1)
        return 0;
    for (i = 0; i < hex_len/2; i++) {
        char b, c = hex[2*i];
        if      (c >= '0' && c <= '9') b = c - '0';
        else if (c >= 'A' && c <= 'F') b = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') b = c - 'a' + 10;
        else                           break;
        b = b << 4;  /* Move half byte up to make room for next half byte */
        c = hex[2*i+1];
        if      (c >= '0' && c <= '9') b += c - '0';
        else if (c >= 'A' && c <= 'F') b += c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') b += c - 'a' + 10;
        else                           break;
        result[i] = (unsigned char)b;
    }
    return i;
}

int main(int argc, const char* argv[])
{
	unsigned int key_char =0;
	unsigned int key_len = 0;
	unsigned int nonce_char = 0;
	unsigned int i = 0;
	size_t bytes_read = 0;
	unsigned char key[32] = {0};
	unsigned char nonce[8];
	unsigned char buffer[BUF_LEN];
    unsigned char cipher_text[4096];
	EVP_CIPHER_CTX ctx;
	unsigned char ctr[16] = {0};
	int outl;
	unsigned int result;

	//return error if missing the 1 arguement
	if (argc != 2)
	{
		fprintf(stderr, "usage: %s arg\n", argv[0]);
		return EXIT_FAILURE;
	}

	// return length of KEY
	key_char = strlen(argv[1]);

	//immediately read NONCE which is at the start of decrypt file
	fread(nonce,1,8,stdin);

	//nonce placed in CTR for chaining
	for(i=0; i<8;i++){ ctr[i]=nonce[i]; }

	//convert hex KEY to Bytes for manipulation
	key_len = hex_to_bytes(key,argv[1],strlen(argv[1]));

	//initialize for block manipulation
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_aes_256_ctr(), NULL, key, ctr, 0);

	//decrypt in chunks of 16 bytes.
	//Standard for AES256 blocks of 128 bits
	do{
		bytes_read = fread(buffer,1,BUF_LEN,stdin);
		if (bytes_read > 0) {
			result = EVP_CipherUpdate(&ctx, cipher_text, &outl, buffer, bytes_read);
			fwrite(cipher_text,1,outl,stdout);
		}
	}while (bytes_read == BUF_LEN);

	//last round of 256 AES does not include shiftrows
	EVP_CipherFinal_ex(&ctx, cipher_text, &outl);
	//write to stdout
	fwrite(cipher_text, 1, outl, stdout);
	EVP_CIPHER_CTX_cleanup(&ctx);

	return EXIT_SUCCESS;

}
