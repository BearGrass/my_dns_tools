#ifndef _ADNS_TOLOWER_H_
#define _ADNS_TOLOWER_H_

#include <stdint.h>
#include <assert.h>

#define ADNS_CHAR_TABLE_SIZE 256

enum {
	/*! \brief Size of the character conversion table. */
	CHAR_TABLE_SIZE = ADNS_CHAR_TABLE_SIZE
};

/*! \brief Character table mapping uppercase letters to lowercase. */
extern const uint8_t char_table[CHAR_TABLE_SIZE];

/*!
 *  * \brief Converts ASCII character to lowercase.
 *   *
 *    * \param c ASCII character code.
 *     *
 *      * \return \a c converted to lowercase (or \a c if not applicable).
 *       */
static inline uint8_t adns_tolower(uint8_t c) {
#if ADNS_CHAR_TABLE_SIZE < 256
	assert(c < CHAR_TABLE_SIZE);
#endif
	return char_table[c];
}

#endif
