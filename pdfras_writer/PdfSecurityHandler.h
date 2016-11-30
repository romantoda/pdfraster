#ifndef _H_PdfSecurityHandler
#define _H_PdfSecurityHandler
#pragma once

#include "PdfOS.h"
#include "PdfAlloc.h"


typedef struct t_pdencrypter {
  void*		cookie;			// data specific to a particular class of encrypter
  pduint32	onr, gen;		// number & generation of current object
  
//todo rt AES256 specific
//todo -quick hack, remembering id of /Encrypt dict
  pduint32 id_encrypt;

  pduint8 o[48];
  pdint16 o_length;
  pduint8 u[48];
  pdint16 u_length;
  pduint8 oe[32];
  pdint16 oe_length;
  pduint8 ue[32];
  pdint16 ue_length;
  pdbool encrypt_metadata;
  pduint8 encryption_key[32];
  pduint8 perms[16];				
} t_pdencrypter;

// functions associated with an (encryption) security handler:
// * Creating an encryption state for a PDF from whatever it needs as input
// * Setting up to encrypt one object, using state+(onr,gen).
// * Predicting the buffer size needed to encrypt n bytes of data
// * Encrypting n bytes of data
// * Writing (or providing) all the encryption metadata

// initialize for encryption of an object.
// The object, or it's first indirect parent, is indirect object <onr, genr>.
extern void pd_encrypt_start_object(t_pdencrypter *crypter, pduint32 onr, pduint32 genr);

// calculate the encrypted size of n bytes of plain data
extern pduint32 pd_encrypted_size(t_pdencrypter *crypter, pduint32 n);

// encrypt n bytes of data
extern void pd_encrypt_data(t_pdencrypter *crypter, pduint8 *outbuf, const pduint8* data, pduint32 n);

//todo rt - rename functions, encapsulate into AES256
t_pdencrypter* pd_encrypt_new(t_pdmempool* pool, void *cookie);
void pd_encrypt_compute_file_encryption_key(t_pdencrypter *crypter);
void pd_encrypt_compute_Alg8(t_pdencrypter *crypter, const char *password);
void pd_encrypt_compute_Alg9(t_pdencrypter *crypter, const char *password);
void pd_encrypt_compute_Alg10(t_pdencrypter *crypter, pdint32 p);

#endif
