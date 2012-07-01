/*
 * ae_wrapper.cpp
 *
 * Wrapper for Authenticated Encryption (AE)
 * using AES Galois/Counter Mode (AES-GCM) 
 *
 * allows optional additional authenticated Data (AEAD)
 *
 * BDEM is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * BDEM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with BDEM.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Oliver Guenther
 * mail@oliverguenther.de
 *
 */

#include "ae_wrapper.hpp"

// hkdf scheme, rfc5869
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include "hkdf.h"

#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/gcm.h>
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::AAD_CHANNEL;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

ae_error_t encrypt_ae(AE_Ciphertext** cts, unsigned char* key, AE_Plaintext* pts) {
    ae_error_t result;
    
    AE_Ciphertext *ct = new AE_Ciphertext;
    
    // Uses CryptoPP::AutoSeededRandomPool for IV
    AutoSeededRandomPool prng;
    
    // Initalize IV using prng
    ct->iv = new unsigned char[AE_IV_LENGTH];
	prng.GenerateBlock(ct->iv, AE_IV_LENGTH);
    
    try {
        // Set up AES-GCM Encryption
		GCM< AES >::Encryption e;
        
        // Initialize scheme with pre-generated IV and the input key
		e.SetKeyWithIV(key, AE_KEY_LENGTH, ct->iv, AE_IV_LENGTH);
        std::string cipher;
        
        // Setup AE Filter into cipher
        AuthenticatedEncryptionFilter ef( e,
                                         new StringSink( cipher ), false, AE_TAG_LENGTH
                                         ); // AuthenticatedEncryptionFilter
        
        // Push data down into Authenticated Encryption (AE) Channel
        ef.ChannelPut(DEFAULT_CHANNEL, pts->plaintext, pts->len);
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        // Copy cipher into ct struct
        ct->ct_len = cipher.size();
        ct->ct = new unsigned char[ct->ct_len];
        memcpy(ct->ct, cipher.data(), ct->ct_len);  
        *cts = ct;
        
        result.error = false;
        return result;
        
	} catch(const CryptoPP::Exception& e) {
        result.error = true;
        result.error_msg = e.what();
        
        // Free previous elements manually, as nothing throws after ct->ct is allocated
        delete ct->iv;
        delete ct;
        
        return result;
	}
    
}


ae_error_t decrypt_ae(AE_Plaintext** pts, unsigned char* key, AE_Ciphertext* cts) {
    ae_error_t result;
    
    
    try {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV(key, AE_KEY_LENGTH, cts->iv, AE_IV_LENGTH);
        
        std::string r_plaintext;
        
        AuthenticatedDecryptionFilter df( d,
                                         new StringSink( r_plaintext ),
                                         AuthenticatedDecryptionFilter::DEFAULT_FLAGS, AE_TAG_LENGTH
                                         ); // AuthenticatedDecryptionFilter
        
        // Push data down into Authenticated Encryption (AE) Channel
        df.ChannelPut(DEFAULT_CHANNEL, cts->ct, cts->ct_len);
        df.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        if( true == df.GetLastResult() ) {
            AE_Plaintext* pt = new AE_Plaintext;
            pt->plaintext = new unsigned char[r_plaintext.size()];
            memcpy(pt->plaintext, r_plaintext.data(), r_plaintext.size());
            pt->len = r_plaintext.size();
            result.error = false;
            
            *pts = pt;
            
            return result;
        }
        
        result.error = true;
        result.error_msg = "Authentication failed";
        return result;
    }
    catch( CryptoPP::Exception& e ) {
        result.error = true;
        result.error_msg = e.what();
        return result;
    }
}


ae_error_t encrypt_aead(AE_Ciphertext** cts, unsigned char* key, AE_Plaintext* pts,   AE_Plaintext* additional) {

    ae_error_t result;
    
    AE_Ciphertext* ct = new AE_Ciphertext;
    
    // Uses CryptoPP::AutoSeededRandomPool for IV
    AutoSeededRandomPool prng;
    
    // Initalize IV using prng
    ct->iv = new unsigned char[AE_IV_LENGTH];
	prng.GenerateBlock(ct->iv, AE_IV_LENGTH);
    
    
    try {
		GCM< AES >::Encryption e;
		e.SetKeyWithIV(key, AE_KEY_LENGTH, ct->iv, AE_IV_LENGTH);
        std::string cipher;
        
        // Setup AE Filter into cipher
        AuthenticatedEncryptionFilter ef( e,
                                         new StringSink( cipher ), false, AE_TAG_LENGTH
                                         ); // AuthenticatedEncryptionFilter
        
        // Push additional into Additional Authenticated Data (AAD) channel        
        ef.ChannelPut(AAD_CHANNEL, additional->plaintext, additional->len);
        ef.ChannelMessageEnd(AAD_CHANNEL);
        
        // Push data down into Authenticated Encryption (AE) Channel
        ef.ChannelPut(DEFAULT_CHANNEL, pts->plaintext, pts->len);
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        // Copy cipher into ct struct
        ct->ct_len = cipher.size();
        ct->ct = new unsigned char[ct->ct_len];
        memcpy(ct->ct, cipher.data(), ct->ct_len);  
        *cts = ct;
        
        result.error = false;
        return result;
        
	} catch(const CryptoPP::Exception& e) {
        result.error = true;
        result.error_msg = e.what();

        // Free previous elements manually, as nothing throws after ct->ct is allocated
        delete ct->iv;
        delete ct;
        
        return result;
	}
}


ae_error_t decrypt_aead(AE_Plaintext** pts, unsigned char* key, AE_Ciphertext* cts,
                        AE_Plaintext* additional) {
    
    ae_error_t result;
    
    try {
        GCM< AES >::Decryption d;
		d.SetKeyWithIV(key, AE_KEY_LENGTH, cts->iv, AE_IV_LENGTH);
        
       
        // Setup AE Decryption filter
        AuthenticatedDecryptionFilter df( d, NULL,
                                         AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                         AuthenticatedDecryptionFilter::THROW_EXCEPTION, AE_TAG_LENGTH );

        /// Determine MAC offset
        size_t mac_offset = cts->ct_len - AE_TAG_LENGTH;
        // Push down MAC data first
        df.ChannelPut(DEFAULT_CHANNEL, cts->ct + mac_offset, AE_TAG_LENGTH );
        
        // Push down Additional Authenticated Data (AAD) for decryption
        df.ChannelPut(AAD_CHANNEL, additional->plaintext, additional->len); 
        
        // Push down Ciphertext
        df.ChannelPut(DEFAULT_CHANNEL, cts->ct, cts->ct_len - AE_TAG_LENGTH);
        
        // END AAD and Regular Channel
        df.ChannelMessageEnd(AAD_CHANNEL);
        df.ChannelMessageEnd(DEFAULT_CHANNEL);
        
        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        if( true == df.GetLastResult() ) {
            
            // Retrieve plaintext
            df.SetRetrievalChannel(DEFAULT_CHANNEL);
            size_t n = df.MaxRetrievable();
            if( n > 0 ) {
                
                AE_Plaintext* recover = new AE_Plaintext;
                
                unsigned char *buf = new unsigned char[n];
                df.Get(buf, n); 
                // Recover plaintext
                recover->len = n;
                recover->plaintext = buf;
                result.error = false;
                *pts = recover;
                
                return result;
            }
        }
        
        result.error = true;
        result.error_msg = "Failed authentication";
        return result;
        
	} catch(const CryptoPP::Exception& e) {
        result.error = true;
        result.error_msg = e.what();
        return result;
	}    
}
