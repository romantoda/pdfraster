#include <string.h>
#include "PdfSecurityHandler.h"
#include "PdfAlloc.h"
#include "openssl/crypto.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/err.h"
#include "openssl/md5.h"
#include <openssl/rand.h>


t_pdencrypter* pd_encrypt_new(t_pdmempool* pool, void *cookie)
{
	t_pdencrypter* crypter = (t_pdencrypter*)pd_alloc(pool, sizeof(t_pdencrypter));
	if (crypter) {
		crypter->cookie = cookie;
	}
	return crypter;
}

void pd_encrypt_free(t_pdencrypter* crypter)
{
	pd_free(crypter);
}

void pd_encrypt_start_object(t_pdencrypter *crypter, pduint32 onr, pduint32 gen)
{
	crypter->onr = onr;
	crypter->gen = gen;
}

pduint32 pd_encrypted_size(t_pdencrypter *crypter, pduint32 n)
{
  // we use AES cbc, with 16 bytes padding (n+16-(n mod 16) )
  // we need to add iv (16 bytes) to the result
	return (n + 16 - (n % 16)) + 16;
}

void pd_encrypt_data(t_pdencrypter *crypter, pduint8 *outbuf, const pduint8* data, pduint32 n)
{
  pduint8 iv[16]; 
  RAND_bytes(iv, sizeof iv);

  int len;
  EVP_CIPHER_CTX aes256;
  EVP_EncryptInit(&aes256, EVP_aes_256_cbc(), crypter->encryption_key, iv);
  // iv needs to go to the result as first 16 bytes
  memcpy(outbuf, iv, 16);
  //put encrypted data after iv
  EVP_EncryptUpdate(&aes256, outbuf+16, &len, (const unsigned char*)data, n);
  EVP_EncryptFinal_ex(&aes256, outbuf + 16 + len, &len);
}

void pd_encrypt_compute_file_encryption_key(t_pdencrypter *crypter)
{
  //todo generate random file encryption key
  pduint8 encrypt_key[] = { 
    0x32, 0x22, 0x15, 0x32, 0x06, 0x65, 0x53, 0x99, 
    0x23, 0x82, 0x48, 0x09, 0x37, 0x45, 0x37, 0x79, 
    0x57, 0x49, 0x31, 0x41, 0x71, 0x02, 0x06, 0x87,
    0x83, 0x51, 0x62, 0x33, 0x90, 0x62, 0x26, 0x11
  };


  memcpy(crypter->encryption_key, encrypt_key, 32);
}

void pd_encrypt_compute_2B(t_pdencrypter *crypter, const char *password, const pduint8 *salt, const pduint8 *additional, pduint8 *hash)
{
  // Algorithm 2.B from ISO 32000-2 to compute hash from password

  pdint32 length = 0;
  if (password != NULL)
    length = pdstrlen(password);
  if (length > 127) 
    length = 127;

  pduint8 K[64]; //SHA256_DIGEST_LENGTH
  pduint16 K_length = 32;
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, (const unsigned char *)password, length);
  SHA256_Update(&sha256, salt, 8);
  if (additional != NULL)
    SHA256_Update(&sha256, additional, 48);
  SHA256_Final(K, &sha256);

  unsigned int last = 0;
  for (unsigned int step = 0; step < 64 || last > step - 32; step++) {

    // step a
    pduint8 K1[15962] = "";
    pdint32 K1_length = 0;
    memcpy((unsigned char*)K1, password, length);
    K1_length += length;
    memcpy(&K1[K1_length], K, K_length);
    K1_length += K_length;
    if (additional != NULL) {
      memcpy(&K1[K1_length], additional, 48);
      K1_length += 48;
    }
    for (int i = 0; i < 6; i++) {
      memcpy(&K1[K1_length], K1, K1_length);
      K1_length = K1_length << 1;
    }

    // step b
    pduint8 E[sizeof(K1)] = "";
    int E_length = 0, len = 0;
    EVP_CIPHER_CTX aes128;
    EVP_EncryptInit(&aes128, EVP_aes_128_cbc(), K, &K[16]);
    EVP_CIPHER_CTX_set_padding(&aes128, 0);
    EVP_EncryptUpdate(&aes128, E, &len, (const unsigned char*)&K1, K1_length);
    E_length = len;
    EVP_EncryptFinal_ex(&aes128, E + len, &len);
    E_length += len;

    // step c
    unsigned int sum = 0;
    for (int i = 0; i < 16; i++)
      sum += E[i];

    // step d
    switch (sum % 3) {
    case 1: {
      SHA512_CTX sha384;
      SHA384_Init(&sha384);
      SHA384_Update(&sha384, (const unsigned char *)E, E_length);
      SHA384_Final(K, &sha384);
      K_length = SHA384_DIGEST_LENGTH;
    }
            break;
    case 2: {
      SHA512_CTX sha512;
      SHA512_Init(&sha512);
      SHA512_Update(&sha512, (const unsigned char *)E, E_length);
      SHA512_Final(K, &sha512);
      K_length = SHA512_DIGEST_LENGTH;
    }
            break;
    case 0:
    default: {
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, (const unsigned char *)E, E_length);
      SHA256_Final(K, &sha256);
      K_length = SHA256_DIGEST_LENGTH;
    }
             break;
    }

    // step e,f
    last = E[E_length - 1];
  }
  memcpy(hash, K, 32);
}

void pd_encrypt_compute_Alg8(t_pdencrypter *crypter, const char *password)
{
  // Algorithm 8 from ISO 32000-2 to compute U and UE
  // we need user password as input 

  //salt is 16 bytes random
  pduint8 salt_u[16];
  RAND_bytes(salt_u, sizeof salt_u);

  // step a
  pd_encrypt_compute_2B(crypter, password, salt_u, NULL, crypter->u);
  memcpy(&crypter->u[32], salt_u, sizeof(salt_u));
  crypter->u_length = 48;

  // step b
  pduint8 ue_key[32];
  pd_encrypt_compute_2B(crypter, password, &salt_u[8], NULL, ue_key);

  pduint8 iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  int len;
  EVP_CIPHER_CTX aes256;
  EVP_EncryptInit(&aes256, EVP_aes_256_cbc(), ue_key ,iv);
  EVP_CIPHER_CTX_set_padding(&aes256, 0);
  EVP_EncryptUpdate(&aes256, crypter->ue, &len, (const unsigned char*)crypter->encryption_key, 32); 
  crypter->ue_length = len;
  EVP_EncryptFinal_ex(&aes256, crypter->ue + len, &len);
  crypter->ue_length += len;
}

void pd_encrypt_compute_Alg9(t_pdencrypter *crypter, const char *password)
{
  //using Algorithm 9 from ISO 32000-2 to compute O and OE
  // we need owner password as input (if owner password is not set, we require user password)
  // need to already have UE so call pd_encrypt_compute_Alg8 first
  
  //salt is 16 bytes random
  pduint8 salt_o[16];
  RAND_bytes(salt_o, sizeof salt_o);

  // step a
  pd_encrypt_compute_2B(crypter, password, salt_o, crypter->u, crypter->o);
  memcpy(&crypter->o[32], salt_o, sizeof(salt_o));
  crypter->o_length = 48;

  // step b
  pduint8 oe_key[32];
  pd_encrypt_compute_2B(crypter, password, &salt_o[8], crypter->u, oe_key);

  pduint8 iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  int len;
  EVP_CIPHER_CTX aes256;
  EVP_EncryptInit(&aes256, EVP_aes_256_cbc(), oe_key, iv);
  EVP_CIPHER_CTX_set_padding(&aes256, 0);
  EVP_EncryptUpdate(&aes256, crypter->oe, &len, (const unsigned char*)crypter->encryption_key, 32); 
  crypter->oe_length = len;
  EVP_EncryptFinal_ex(&aes256, crypter->oe + len, &len);
  crypter->oe_length += len;
}


void pd_encrypt_compute_Alg10(t_pdencrypter *crypter, pdint32 p)
{
  // using Algorithm 10 from ISO 32000-2 to compute compute the encryption dictionary’s Perms (permissions)

  // steps a,b
  pduint8 perms_buffer[16];
  perms_buffer[0] = (pduint8)(p & 0xFF);
  perms_buffer[1] = (pduint8)((p >> 8) & 0xFF);
  perms_buffer[2] = (pduint8)((p >> 16) & 0xFF);
  perms_buffer[3] = (pduint8)((p >> 24) & 0xFF);
  perms_buffer[4] = (pduint8)(0xFF);
  perms_buffer[5] = (pduint8)(0xFF);
  perms_buffer[6] = (pduint8)(0xFF);
  perms_buffer[7] = (pduint8)(0xFF);

  // step c
  perms_buffer[8] = crypter->encrypt_metadata ? 'T' : 'F';

  // step d
  perms_buffer[9] = 'a';
  perms_buffer[10] = 'd';
  perms_buffer[11] = 'b';

  // step e - //random numbers. let's use: 'TwAi'
  perms_buffer[12] = 'T';
  perms_buffer[13] = 'w';
  perms_buffer[14] = 'A';
  perms_buffer[15] = 'i';

  // step f
  pduint8 iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  int len,perms_len;
  EVP_CIPHER_CTX aes256;
  EVP_EncryptInit(&aes256, EVP_aes_256_ecb(), crypter->encryption_key, iv);
  EVP_CIPHER_CTX_set_padding(&aes256, 0);
  EVP_EncryptUpdate(&aes256, crypter->perms, &len, perms_buffer, sizeof perms_buffer);
  perms_len = len;
  EVP_EncryptFinal_ex(&aes256, crypter->perms + len, &len);
  perms_len += len;
}