Whitebox-crypto-AES
===================
[![Build Status](https://travis-ci.org/ph4r05/Whitebox-crypto-AES.svg?branch=master)](https://travis-ci.org/ph4r05/Whitebox-crypto-AES)
[![Coverity Status](https://scan.coverity.com/projects/7179/badge.svg)](https://scan.coverity.com/projects/ph4r05-whitebox-crypto-aes)

Whitebox cryptography AES implementation.

This repository contains a C++ implementation of:
 * Complete whitebox [AES]-128 scheme introduced by [Chow] et al [2]. Implements/uses input/output encodings, mixing bijections, external encodings.
 * Complete whitebox [AES]-128 scheme introduced by [Karroumi] [3] which uses an idea of dual AES ciphers (using a different generating polynomial for AES cipher) for creating a stronger AES whitebox scheme.
 * Implementation of the [BGE] Attack on [Chow]'s AES whitebox implementation found by [Billet] et al [4]. Attack uses whitebox AES generator to create a random instance of whitebox AES scheme with secret key K embedded in the implementation. The attack then recovers the secret key K from the tables representing the given instance. This BGE attack also breaks scheme proposed by [Karroumi] what I found out while working on my [diploma] thesis.
 
The implementation contains:
 * Whitebox AES code generator in both [Chow] and [Karroumi] schemes. It generates a randomized whitebox AES instance with embedded encryption key K which can be used either for encryption or for decryption. Instance can be serialized to a file. 
 * Code for running generated whitebox AES instance for encryption/decryption.
 * BGE key recovery attack on a generated whitebox AES instance.
 * Unit tests.
 
You also might be interested in my [Java] implementation of the Chow's whitebox AES scheme.
In my [diploma] thesis I suggest modifications and improvements for a new whitebox-suited symmetric-key encryption algorithm based on AES.


[AES]: http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
[Chow]: http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.59.7710
[Karroumi]: http://dl.acm.org/citation.cfm?id=2041060
[Billet]: http://bo.blackowl.org/s/papers/waes.pdf
[diploma]: http://is.muni.cz/th/325219/fi_m/thesis.pdf
[Java]: https://github.com/ph4r05/Whitebox-crypto-AES-java

[2]: Stanley Chow, Phil Eisen, Harold Johnson, and Paul C. Van Oorschot. White-box cryptography and an AES implementation. In Proceedings of the Ninth Workshop on Selected Areas in Cryptography (SAC 2002, pages 250–270. Springer-Verlag, 2002.

[3]: Mohamed Karroumi. Protecting white-box AES with dual ciphers. In Proceedings of the 13th international conference on Information security and cryptology, ICISC’10, pages 278–291, Berlin, Heidelberg, 2011. Springer-Verlag. ISBN 978-3-642-24208-3. 

[4]: Olivier Billet, Henri Gilbert, and Charaf Ech-Chatbi. Cryptanalysis of a white box AES implementation. In Proceedings of the 11th international conference on Selected Areas in Cryptography, SAC’04, pages 227–240, Berlin, Heidelberg, 2005. Springer-Verlag. ISBN 3-540-24327-5, 978-3-540-24327-4. doi: 10.1007/978-3-540-30564-4_16.

Dependencies
=======
* C++0x and higher
* CMake 2.8+
* [NTL] 6.0.0+
* boost_iostreams 1.55+
* boost_serialization 1.55+
* boost_program_options 1.55+
* boost_random 1.55+

Description:
* [NTL] math library is used for computation in finite fields & algebra. ~~NTL is licensed under GPL thus this implementation also has to be GPL.~~
* Boost library for serialization of the scheme instance & program input parameters parsing. Version 1.55


Building
=======
* Travis is configured for the project so in case of any problems please refer to the travis configuration file.
* Install dependencies. For installing NTL you can use provided scripts `install-ntl.sh` or `install-ntl-cached.sh`
* Use cmake to build
```bash
mkdir build-debug
cd build-debug
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

License
=======
Code is published under license: GPLv3 [http://www.gnu.org/licenses/gpl-3.0.html]. This license holds from the first commit.
I also require to include my copyright header in files if you decide to use my source codes.

Using GPL in short means that if you incorporate this source code to your application, it has to be also published under GPLv3. Also if you make any improvement to my source code and you will use improved version you are obliged to publish improved version as well.

If this license does not fit to you, drop me an email, I am sure we can negotiate somehow.

** UPDATE 31.01.2017 **
<br/>
[NTL] is now licensed under LGPL v2.1+ so I can relicense the code to LGPL v2.1+ by a written permission.
So the code is by default GPLv3 licensed, but if you drop me an email I will give you LGPL v2.1+ license.
I am also free to talk about other licensing options.

Donating
========

This implementation is an open source. If you like the code or you do find it useful please feel free to donate to the
author whatever amount you would like by clicking on the paypal button below.
And if you don't feel like donating, that's OK too.

[![](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=XK6RLD768RGGJ&lc=SK&item_name=ph4r05&item_number=Whitebox%2dcrypto%2dAES%2egit&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)

Bitcoin:

![1DBr1tfuqv6xphg5rzNTPxqiUbqbRHrM2E](https://deadcode.me/btc-whitebox.png)<br />1DBr1tfuqv6xphg5rzNTPxqiUbqbRHrM2E

Contributing
=======
If you want to improve my code by extending it to AES-256 or implementing other whitebox AES schemes do not hesitate to submit a pull request. Please also consider it if you find some bug in the code. I am not actively developing this code at the moment but I will review the pull requests. Thanks!

[NTL]: http://www.shoup.net/ntl/
