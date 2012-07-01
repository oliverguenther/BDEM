/**
 *     Copyright (c), 2010, ClickLock.com
 *
 *     Permission is hereby granted, free of charge, to any person obtaining a copy
 *     of this software and associated documentation files (the "Software"), to deal
 *     in the Software without restriction, including without limitation the rights
 *     to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *     copies of the Software, and to permit persons to whom the Software is
 *     furnished to do so, subject to the following conditions:
 * 
 *     The above copyright notice and this permission notice shall be included in
 *     all copies or substantial portions of the Software.
 *
 *     @brief Hash-based KDF as defined in RFC 5869
 *     @see http://www.rfc-editor.org/rfc/rfc5869.txt
 *     @author Nils Durner, Travis Jensen
 *
 *     Portions of this file based on:
 *         https://gnunet.org/svn/gnunet/src/util/crypto_hkdf.c
 *     with the following information, copyright and license:
 *
 *     Copyright (c) 2010 Nils Durner
 * 
 */

#ifndef CRYPTOPP_HKDF_H
#define CRYPTOPP_HKDF_H

#include <cstdlib>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hmac.h>

NAMESPACE_BEGIN(CryptoPP)

/**
 * Key deriver based on HKDF. For more details on the HKDF algorithm, see RFC 5869
 * (http://tools.ietf.org/html/rfc5869).
 *
 * T is the hash transform to use for the extraction phase.
 */
template <class T> class HMACKeyDerivationFunction {
public:
    HMACKeyDerivationFunction();
    virtual ~HMACKeyDerivationFunction();
    
    size_t MaxDerivedKeyLength() const { T t; return 255 * t.DigestSize(); }
    /**
     * Sets the Source Key Material
     */
    virtual void SetKey(const byte *skm, size_t skmLen, 
                        const byte *salt = NULL, size_t saltLen = 0);
    /**
     * Adds additional context information to the hash
     */
    virtual void Update(const byte *context, size_t contextLen);
    
    /**
     * Computes the actual derived key of the given length. keyLen must be less than
     * or equal to HMACKeyDerivationFunction::MaxDerivedKeyLength()
     */
    virtual void Finish(byte *key, size_t keyLen);
    
    /**
     * Shortcut for deriving a key if you don't want to call Update and Finish
     * yourself.
     */
    virtual void DeriveKey(byte *derived, size_t derivedLen, 
                           const byte *skm, const int skmLen,
                           const byte * salt = NULL, const int saltLen = 0,
                           const byte * context = NULL, const int contextLen = 0);
    
protected:
    byte * sourceKey;
    size_t sourceKeyLen;
    byte * salt;
    size_t saltLen;
    byte * context;
    int contextLen;
    CryptoPP::HMAC<T> hmac;
    
    /**
     * (Re-)allocates a buffer, clears the memory (only the newly allocated part),
     * performing error checking and throwing an exception if the allocation fails.  
     * Passing 0 in for numBytes will free the buffer and return NULL.
     */
    byte * AllocBuffer(size_t new_size, byte * prevBuffer = NULL, size_t prev_size = 0);
};

template <class T>
HMACKeyDerivationFunction<T>::HMACKeyDerivationFunction()
:sourceKey(NULL), sourceKeyLen(0), salt(NULL), saltLen(0),
context(NULL), contextLen(0), hmac() {
}


template <class T>
HMACKeyDerivationFunction<T>::~HMACKeyDerivationFunction() {
    if (sourceKey) {
        free(sourceKey);
    }
    if (salt) {
        free(salt);
    }
    if (context) {
        free(context);
    }
    sourceKeyLen = saltLen = contextLen = 0;
    sourceKey = salt = context = NULL;
}

template <class T>
byte * HMACKeyDerivationFunction<T>::AllocBuffer(size_t new_size, byte * prevBuffer, 
                                                 size_t prev_size ) {
    if (new_size <= 0 && prevBuffer == NULL) {
        throw InvalidArgument("You must either specify a positive size of buffer to allocate or give a buffer to free.");
    }
    
    byte * buffer = NULL;
    if (new_size > 0) {
        buffer = (byte *) realloc(prevBuffer, new_size);
        if (buffer == NULL) {
            throw OS_Error(Exception::OTHER_ERROR, 
                           "Unable to allocation buffer",
                           "Alloc", 7);
        } 
        
        if (buffer && new_size > prev_size) {
            ::memset(buffer + prev_size, 0, (new_size - prev_size));
        }
    }
    else {
        // realloc is supposed to free if new_size is zero, but in practice, it
        // doesn't seem to work. There are some indications it might be platform
        // specific. We'll explicitly free just to be sure.
        free(prevBuffer);
    }
    return buffer;
}


template <class T>
void HMACKeyDerivationFunction<T>::SetKey(const byte *skm, size_t skmLen, 
                                          const byte *salt, size_t saltLen) {
    if (skm == NULL || skmLen <= 0)  {
        throw InvalidArgument("Source Key cannot be empty");
    }
    sourceKeyLen = skmLen;
    sourceKey = this->AllocBuffer(skmLen, sourceKey);
    ::memcpy(sourceKey, skm, sourceKeyLen);
    
    if (salt != NULL && saltLen > 0) {
        this->saltLen = saltLen;
        this->salt = this->AllocBuffer(saltLen);
        ::memcpy(this->salt, salt, saltLen);
    }
}

template <class T>
void HMACKeyDerivationFunction<T>::Update(const byte *ctx, size_t ctxLen) {
    if (ctx == NULL || ctxLen <= 0)  {
        throw InvalidArgument("Context and length cannot be empty or negative");
    }
    int curLen = contextLen;
    int newLen = curLen + ctxLen;
    context = this->AllocBuffer(newLen, context, curLen);
    ::memcpy(context + curLen, ctx, ctxLen);
    contextLen = newLen;
}

template <class T>
void HMACKeyDerivationFunction<T>::DeriveKey(byte *derived, size_t derivedLen, 
                                             const byte *skm, const int skmLen,
                                             const byte * salt, const int saltLen,
                                             const byte * context, const int contextLen) {
    this->SetKey(skm, skmLen, salt, saltLen);
    if (context && contextLen > 0) {
        this->Update(context, contextLen);
    }
    this->Finish(derived, derivedLen);
}

template <class T>
void HMACKeyDerivationFunction<T>::Finish(byte *key, size_t keyLen) {
    unsigned long i, t, d;
    T hash;
    HMAC<T> hmac;
    
    unsigned int hash_len = hash.DigestSize();
    byte prk[hash_len];
    int ret;
    
    if (keyLen == 0)
        throw InvalidArgument("HKDF: hash function length can't be zero");
    
    // FIXME: what is the check for?
    if (keyLen > (2 ^ 32 * hash_len))
        throw InvalidArgument("HDKF: output length is too big?");
    
    ::memset (key, 0, keyLen);
    ::memset (prk, 0, hash_len);
    
    hmac.SetKey(salt, saltLen);
    hmac.CalculateTruncatedDigest(prk, sizeof(prk), sourceKey, sourceKeyLen);
    
    t = keyLen / hash_len;
    d = keyLen % hash_len;
    byte hc[hash_len];
    int hmacLen = hmac.DigestSize();
    ::memset (hc, hash_len, 0);
    
    /* K(1) */
    {
        size_t plain_len = hash_len + contextLen + 1;
        byte plain[plain_len];
        byte *dst;
        
        dst = plain + hash_len;
        
        if (contextLen > 0) {
            ::memcpy (dst, context, contextLen);
        }
        if (t > 0)
        {
            ::memset (plain + hash_len + contextLen, 1, 1);
            hmac.SetKey(prk, hash_len);
            hmac.CalculateDigest(hc, &plain[hash_len], contextLen + 1);
            ::memcpy (key, hc, keyLen);
            key += hash_len;
        }
        
        /* K(i+1) */
        for (i = 1; i < t; i++)
        {
            ::memcpy (plain, key - hash_len, hash_len);
            ::memset (plain + hash_len + contextLen, i + 1, 1);
            hmac.SetKey(prk, hash_len);
            hmac.CalculateDigest(hc, plain, plain_len);
            ::memcpy (key, hc, hash_len);
            key += hash_len;
        }
        
        /* K(t):d */
        if (d > 0)
        {
            if (t > 0)
                ::memcpy (plain, key - hash_len, hash_len);
            ::memset (plain + hash_len + contextLen, i + 1, 1);
            hmac.SetKey(prk, hash_len);
            if (t > 0)
                hmac.CalculateDigest(hc, plain, plain_len);
            else
                hmac.CalculateDigest(hc, plain + hash_len, plain_len - hash_len);
            
            ::memcpy (key, hc, d);
        }
    }
}

NAMESPACE_END

#endif
