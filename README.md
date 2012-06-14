#Broadcast Data Encapsulation using AES Galois/Counter mode of operation

BDEM provides a C++ implementation of a Data Encapsulation Mechanism utilizing the [PBC\_BKEM](http://github.com/oliverguenther/PBC_BKEM) implementation of a 
Broadcast Key Encapsulation mechanism as proposed in the [Boneh-Gentry-Waters Broadcast Encryption scheme](http://crypto.stanford.edu/~dabo/abstracts/broadcast.html) (Sec. 3.2, General Construction).

It depends on the [Crypto++](http://cryptopp.com) C++ cryptographic library, especially on their implementation of Authenticated Encryption with Additional Data (AEAD) using AES with the [Galois/Counter mode of operation (GCM)](http://www.cryptopp.com/wiki/GCM_Mode#AEAD).

## Contact
Oliver Günther, mail@oliverguenther.de

##LICENSE

BDEM is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

BDEM is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
