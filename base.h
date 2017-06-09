/*
 * base.h
 *
 *  Created on: Apr 11, 2013
 *      Author: ph4r05
 */

#ifndef BASE_H_
#define BASE_H_

#ifdef FULL_WBC_CODE_SUITE_WITH_DECRYPTION_TOO

#define AES_BGE_ATTACK 1
#define WBAES_BOOST_SERIALIZATION 1
#define FORCE_DETERMINISM 1

int phrand();

#endif /* FULL_WBC_CODE_SUITE_WITH_DECRYPTION_TOO */

#endif /* BASE_H_ */
