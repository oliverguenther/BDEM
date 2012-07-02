#ifndef H_AE_WRAPPER
#define H_AE_WRAPPER

#include <string>

#include <gmpxx.h>

extern "C" {
#include "../PBC_BKEM/bkem.h"
}

#pragma mark -
#pragma mark AE defines, return structs

// AES-GCM Key length (256 bits)
#define AE_KEY_LENGTH 32

// AES-GCM IV length (96 bits) as recommended in 
// (2.1., McGrew, Viega: "The Galois / Counter Mode of Operation")
#define AE_IV_LENGTH 12

// AES-GCM MAC tag length (128 bits)
#define AE_TAG_LENGTH 16

/**
 * @typedef Authenticated Encryption ciphertext struct
 */
struct AE_Ciphertext {
    ~AE_Ciphertext() {
        if (ct) delete[] ct;
        if (iv) delete[] iv;
    }
    
    // The length of the ciphertext array
    size_t ct_len;
    
    // stores actual ciphertext and MAC tag
    unsigned char* ct;
    
    // The IV used to compute ct of size AES_IV_LENGTH
    unsigned char* iv;
};

struct AE_Plaintext {
    ~AE_Plaintext() {
        if (plaintext) delete[] plaintext;
    }
    
    // Length of the recovered plaintext
    size_t len;
    
    // Stores recovered plaintext
    unsigned char* plaintext;
};

// Wraps result and error information
typedef struct {
    // Is set to true, if operation failed
    bool error;
    
    // Contains an informal error code/message
    std::string error_msg;
    
} ae_error_t;


#pragma mark -
#pragma mark AE/AD wrappers 


/**
 * @fn encrypt_ae
 * @brief Encrypt data of size len using Authenticated Encryption (with AES-GCM).
 * @param cts The result of this operation will be stored in an ae_ciphertext_t at *cts
 * @param key The symmetric key of length AE_KEY_LENGTH
 * @param pts The ae_plaintext_t data struct to encrypt
 * @return an ae_error_t to check whether encryption succeeded
 */
ae_error_t encrypt_ae(AE_Ciphertext** cts, unsigned char* key, AE_Plaintext* pts);


/**
 * @fn decrypt_ae
 * @brief Decrypt data using Authenticated Encryption (with AES-GCM).
 * @param pts points to ae_plaintext_t data struct, will be allocated and 
 * returned from this method
 * @param key The symmetric key of length AE_KEY_LENGTH
 * @param cts The ae_ciphertext_t containing the ciphertext and IV
  * @return an ae_error_t to check whether decryption succeeded
 */
ae_error_t decrypt_ae(AE_Plaintext** pts, unsigned char* key, AE_Ciphertext* cts);

/**
 * @fn encrypt_aead
 * @brief Encrypt data of size len using Authenticated Encryption 
 * with Additional Data (with AES-GCM).
 * @param cts The result of this operation will be stored in an ae_ciphertext_t at *cts.
 * The result does not include the additional data, but only authenticates 
 * it using the MAC tag
 * @param key The symmetric key of length AE_KEY_LENGTH
 * @param plaintext The plaintext ae_plaintext_t to encrypt and authenticate
 * @param additional The additional ae_plaintext_t data to authenticate _only_
 * @return an ae_error_t to check whether encryption succeeded
 */
ae_error_t encrypt_aead(AE_Ciphertext** cts, unsigned char* key, AE_Plaintext* plaintext,
                  AE_Plaintext* additional);

/**
 * @fn decrypt_aead
 * @brief Decrypts data of size len using Authenticated Encryption 
 * with Additional Data (with AES-GCM).
 * @param pts The result of this operation will be stored in an ae_plaintext_t at *pts
 * @param key The symmetric key of length AE_KEY_LENGTH
 * @param cts The ae_ciphertext_t data to decrypt and authenticate
 * @param additional The ae_plaintext_t data to authenticate _only_
 * @return an ae_error_t to check whether decryption succeeded
 */
ae_error_t decrypt_aead(AE_Plaintext** pts, unsigned char* key, AE_Ciphertext* cts, AE_Plaintext* additional);

#pragma mark -
#pragma mark HKDF 


/**
 * @fn derivate_encryption_key
 * @brief Derives a symmetric encryption key of length keylen using the HMAC-based 
 * Extract-and-Expand key derivation function (HKDF) and uses a PBC element as input keying material.
 * See http://tools.ietf.org/html/rfc5869 for more information
 * @param key Output Keying Material (OKM) from the HKDF
 * @param key_len desired output key length in bytes
 * @param salt Input salt or NULL
 * @param salt_len length of input salt
 * @param bes_key a PBC element (the BES private key) to derive data from
 */
void derivate_encryption_key(unsigned char *key, size_t keylen, unsigned char *salt, size_t salt_len, element_t bes_key);

#endif