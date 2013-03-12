
/*               Minor Changes for endiannes (for mcrypt)                     */
/*               --Nikos                                                      */
/******************************************************************************/
/*                                                                            */
/* I N T E R N A T I O N A L  D A T A  E N C R Y P T I O N  A L G O R I T H M */
/*                                                                            */
/******************************************************************************/
/* Author:       Richard De Moliner (demoliner@isi.ee.ethz.ch)                */
/*               Signal and Information Processing Laboratory                 */
/*               Swiss Federal Institute of Technology                        */
/*               CH-8092 Zuerich, Switzerland                                 */

/* Created:      April 23, 1992                                               */
/* Changes:      November 16, 1993 (support of ANSI-C and C++)                */
/* System:       SUN SPARCstation, SUN acc ANSI-C-Compiler, SUN-OS 4.1.3      */
/******************************************************************************/

/* $Id: idea.c,v 1.3 2000/10/07 18:27:25 nmav Exp $ */

#include "../../lib/libdefs.h"
#include "../../lib/mcrypt_modules.h"
#include "idea.h"

#define mulMod        0x10001	/* 2**16 + 1                                    */
#define ones           0xFFFF	/* 2**16 - 1                                    */

#define _mcrypt_set_key idea_LTX__mcrypt_set_key
#define _mcrypt_encrypt idea_LTX__mcrypt_encrypt
#define _mcrypt_decrypt idea_LTX__mcrypt_decrypt
#define _mcrypt_get_size idea_LTX__mcrypt_get_size
#define _mcrypt_get_block_size idea_LTX__mcrypt_get_block_size
#define _is_block_algorithm idea_LTX__is_block_algorithm
#define _mcrypt_get_key_size idea_LTX__mcrypt_get_key_size
#define _mcrypt_get_supported_key_sizes idea_LTX__mcrypt_get_supported_key_sizes
#define _mcrypt_get_algorithms_name idea_LTX__mcrypt_get_algorithms_name
#define _mcrypt_self_test idea_LTX__mcrypt_self_test
#define _mcrypt_algorithm_version idea_LTX__mcrypt_algorithm_version

/******************************************************************************/
/* Multiplication in the multiplicative group, a = a * b                      */
/* pre:  0 <= a <= 0xFFFF.                                                    */
/*       0 <= b <= 0xFFFF.                                                    */
/* post: 'a' and 'b' have been modified.                                      */
/*       a = a * b; where '*' is multiplication in the multiplicative group.  */
/* note: This implementation of '*' is not complete. To bee complete the      */
/*       result has to bee masked (MUL(a, b); a &= ones;).                    */

#define Mul(a, b)                                                              \
  if (a == 0) a = mulMod - b;                                                  \
  else if (b == 0) a = mulMod - a;                                             \
  else {                                                                       \
    a *= b;                                                                    \
    if ((a & ones) >= (b = a >> 16)) a -= b;                                   \
    else a += mulMod - b;                                                      \
  }				/* Mul */

/******************************************************************************/
/* Encryption and decryption algorithm IDEA. Depending on the value of 'key'  */
/* 'Idea_Crypt' either encrypts or decrypts 'dataIn'. The result is stored    */
/* in 'dataOut'.                                                              */
/* pre:  'dataIn'  contains the plain/cipher-text block.                      */
/*       'key'     contains the encryption/decryption key.                    */
/* post: 'dataOut' contains the cipher/plain-text block.                      */

void _mcrypt_encrypt(IDEA_KEY * key, Idea_Data dataIn)
{
	register word32 x0, x1, x2, x3, t0, t1, t2;
	int round, i = 0;

#ifdef WORDS_BIGENDIAN
	x0 = (word32) (byteswap16(dataIn[0]));
	x1 = (word32) (byteswap16(dataIn[1]));
	x2 = (word32) (byteswap16(dataIn[2]));
	x3 = (word32) (byteswap16(dataIn[3]));
#else
	x0 = (word32) ((dataIn[0]));
	x1 = (word32) ((dataIn[1]));
	x2 = (word32) ((dataIn[2]));
	x3 = (word32) ((dataIn[3]));
#endif

	for (round = Idea_nofRound; round > 0; round--) {
		t1 = (word32) key->Idea_Key[i++];
		x1 += (word32) key->Idea_Key[i++];
		x2 += (word32) key->Idea_Key[i++];
		x2 &= ones;
		t2 = (word32) key->Idea_Key[i++];
		Mul(x0, t1);
		x0 &= ones;
		Mul(x3, t2);
		t0 = (word32) key->Idea_Key[i++];
		t1 = x0 ^ x2;
		Mul(t0, t1);
		t0 &= ones;
		t1 = (word32) key->Idea_Key[i++];
		t2 = ((x1 ^ x3) + t0) & ones;
		Mul(t1, t2);
		t1 &= ones;
		t0 += t1;
		x0 ^= t1;
		x3 ^= t0;
		x3 &= ones;
		t0 ^= x1;
		x1 = x2 ^ t1;
		x2 = t0;
	}
	t0 = (word32) key->Idea_Key[i++];
	Mul(x0, t0);
#ifdef WORDS_BIGENDIAN
	dataIn[0] = byteswap16((word16) (x0 & ones));
	dataIn[1] =
	    byteswap16((word16)
			(((word32) key->Idea_Key[i++] + x2) & ones));
	dataIn[2] =
	    byteswap16((word16)
			(((word32) key->Idea_Key[i++] + x1) & ones));
	t0 = (word32) key->Idea_Key[i];
	Mul(x3, t0);
	dataIn[3] = byteswap16((word16) (x3 & ones));
#else
	dataIn[0] = ((word16) (x0 & ones));
	dataIn[1] = ((word16) (((word32) key->Idea_Key[i++] + x2) & ones));
	dataIn[2] = ((word16) (((word32) key->Idea_Key[i++] + x1) & ones));
	t0 = (word32) key->Idea_Key[i];
	Mul(x3, t0);
	dataIn[3] = ((word16) (x3 & ones));
#endif
}				/* Idea_Crypt */


void _mcrypt_decrypt(IDEA_KEY * key, Idea_Data dataIn)
{
	register word32 x0, x1, x2, x3, t0, t1, t2;
	int round, i = 0;

#ifdef WORDS_BIGENDIAN
	x0 = (word32) (byteswap16(dataIn[0]));
	x1 = (word32) (byteswap16(dataIn[1]));
	x2 = (word32) (byteswap16(dataIn[2]));
	x3 = (word32) (byteswap16(dataIn[3]));
#else
	x0 = (word32) ((dataIn[0]));
	x1 = (word32) ((dataIn[1]));
	x2 = (word32) ((dataIn[2]));
	x3 = (word32) ((dataIn[3]));
#endif

	for (round = Idea_nofRound; round > 0; round--) {
		t1 = (word32) key->Idea_inverted_Key[i++];
		x1 += (word32) key->Idea_inverted_Key[i++];
		x2 += (word32) key->Idea_inverted_Key[i++];
		x2 &= ones;
		t2 = (word32) key->Idea_inverted_Key[i++];
		Mul(x0, t1);
		x0 &= ones;
		Mul(x3, t2);
		t0 = (word32) key->Idea_inverted_Key[i++];
		t1 = x0 ^ x2;
		Mul(t0, t1);
		t0 &= ones;
		t1 = (word32) key->Idea_inverted_Key[i++];
		t2 = ((x1 ^ x3) + t0) & ones;
		Mul(t1, t2);
		t1 &= ones;
		t0 += t1;
		x0 ^= t1;
		x3 ^= t0;
		x3 &= ones;
		t0 ^= x1;
		x1 = x2 ^ t1;
		x2 = t0;
	}
	t0 = (word32) key->Idea_inverted_Key[i++];
	Mul(x0, t0);
#ifdef WORDS_BIGENDIAN
	dataIn[0] = byteswap16((word16) (x0 & ones));
	dataIn[1] =
	    byteswap16((word16)
			(((word32) key->Idea_inverted_Key[i++] + x2) &
			 ones));
	dataIn[2] =
	    byteswap16((word16)
			(((word32) key->Idea_inverted_Key[i++] + x1) &
			 ones));
	t0 = (word32) key->Idea_inverted_Key[i];
	Mul(x3, t0);
	dataIn[3] = byteswap16((word16) (x3 & ones));
#else
	dataIn[0] = ((word16) (x0 & ones));
	dataIn[1] =
	    ((word16)
	     (((word32) key->Idea_inverted_Key[i++] + x2) & ones));
	dataIn[2] =
	    ((word16)
	     (((word32) key->Idea_inverted_Key[i++] + x1) & ones));
	t0 = (word32) key->Idea_inverted_Key[i];
	Mul(x3, t0);
	dataIn[3] = ((word16) (x3 & ones));
#endif
}				/* Idea_Crypt */



/******************************************************************************/
/* Multiplicative Inverse by Extended Stein Greatest Common Divisor Algorithm.*/
/* pre:  0 <= x <= 0xFFFF.                                                    */
/* post: x * MulInv(x) == 1, where '*' is multiplication in the               */
/*                           multiplicative group.                            */
/* static was removed */

word16 MulInv(word16 x)
{

	register sword32 n1, n2, N, a1, a2, b1, b2;

	if (x <= 1)
		return x;
	n1 = N = (sword32) x;
	n2 = mulMod;
	a1 = b2 = 1;
	a2 = b1 = 0;
	do {
		while ((n1 & 1) == 0) {
			if (a1 & 1) {
				if (a1 < 0) {
					a1 += mulMod;
					b1 -= N;
				} else {
					a1 -= mulMod;
					b1 += N;
				}
			}
			n1 >>= 1;
			a1 >>= 1;
			b1 >>= 1;
		}
		if (n1 < n2)
			do {
				n2 -= n1;
				a2 -= a1;
				b2 -= b1;
				if (n2 == 0)
					return (word16) (a1 <
							 0 ? a1 +
							 mulMod : a1);
				while ((n2 & 1) == 0) {
					if (a2 & 1) {
						if (a2 < 0) {
							a2 += mulMod;
							b2 -= N;
						} else {
							a2 -= mulMod;
							b2 += N;
						}
					}
					n2 >>= 1;
					a2 >>= 1;
					b2 >>= 1;
				}
			} while (n1 <= n2);
		n1 -= n2;
		a1 -= a2;
		b1 -= b2;
	} while (n1);
	return (word16) (a2 < 0 ? a2 + mulMod : a2);
}				/* MulInv */

/******************************************************************************/
/* Additive Inverse.                                                          */
/* pre:  0 <= x <= 0xFFFF.                                                    */
/* post: x + AddInv(x) == 0, where '+' is addition in the additive group.     */

#define AddInv(x)  (-x & ones)

/******************************************************************************/
/* Inverts a decryption/encrytion key to a encrytion/decryption key.          */
/* pre:  'key'    contains the encryption/decryption key.                     */
/* post: 'invKey' contains the decryption/encryption key.                     */

void _mcrypt_Idea_InvertKey(IDEA_KEY * key)
{
	register word16 t;
	register int lo, hi, i;

	lo = 0;
	hi = 6 * Idea_nofRound;
	t = MulInv(key->Idea_Key[lo]);
	key->Idea_inverted_Key[lo++] = MulInv(key->Idea_Key[hi]);
	key->Idea_inverted_Key[hi++] = t;
	t = AddInv(key->Idea_Key[lo]);
	key->Idea_inverted_Key[lo++] = AddInv(key->Idea_Key[hi]);
	key->Idea_inverted_Key[hi++] = t;
	t = AddInv(key->Idea_Key[lo]);
	key->Idea_inverted_Key[lo++] = AddInv(key->Idea_Key[hi]);
	key->Idea_inverted_Key[hi++] = t;
	t = MulInv(key->Idea_Key[lo]);
	key->Idea_inverted_Key[lo++] = MulInv(key->Idea_Key[hi]);
	key->Idea_inverted_Key[hi] = t;
	for (i = (Idea_nofRound - 1) / 2; i != 0; i--) {
		t = key->Idea_Key[lo];
		key->Idea_inverted_Key[lo++] = key->Idea_Key[hi -= 5];
		key->Idea_inverted_Key[hi++] = t;
		t = key->Idea_Key[lo];
		key->Idea_inverted_Key[lo++] = key->Idea_Key[hi];
		key->Idea_inverted_Key[hi] = t;
		t = MulInv(key->Idea_Key[lo]);
		key->Idea_inverted_Key[lo++] =
		    MulInv(key->Idea_Key[hi -= 5]);
		key->Idea_inverted_Key[hi++] = t;
		t = AddInv(key->Idea_Key[lo]);
		key->Idea_inverted_Key[lo++] = AddInv(key->Idea_Key[++hi]);
		key->Idea_inverted_Key[hi--] = t;
		t = AddInv(key->Idea_Key[lo]);
		key->Idea_inverted_Key[lo++] = AddInv(key->Idea_Key[hi]);
		key->Idea_inverted_Key[hi++] = t;
		t = MulInv(key->Idea_Key[lo]);
		key->Idea_inverted_Key[lo++] = MulInv(key->Idea_Key[++hi]);
		key->Idea_inverted_Key[hi] = t;
	}
#if (Idea_nofRound % 2 == 0)
	t = key->Idea_Key[lo];
	key->Idea_inverted_Key[lo++] = key->Idea_Key[hi -= 5];
	key->Idea_inverted_Key[hi++] = t;
	t = key->Idea_Key[lo];
	key->Idea_inverted_Key[lo++] = key->Idea_Key[hi];
	key->Idea_inverted_Key[hi] = t;
	key->Idea_inverted_Key[lo] = MulInv(key->Idea_Key[lo]);
	lo++;
	t = AddInv(key->Idea_Key[lo]);
	key->Idea_inverted_Key[lo] = AddInv(key->Idea_Key[lo + 1]);
	lo++;
	key->Idea_inverted_Key[lo++] = t;
	key->Idea_inverted_Key[lo] = MulInv(key->Idea_Key[lo]);
#else
	key->Idea_inverted_Key[lo] = key->Idea_Key[lo];
	lo++;
	key->Idea_inverted_Key[lo] = key->Idea_Key[lo];
#endif
}				/* Idea_InvertKey */

/******************************************************************************/
/* Expands a user key of 128 bits to a full encryption key                    */
/* pre:  'userKey' contains the 128 bit user key                              */
/* post: 'key'     contains the encryption key                                */

int _mcrypt_set_key(IDEA_KEY * key, Idea_UserKey userKey, int len)
{
	register int i;

#if (Idea_keyLen <= Idea_userKeyLen)
# ifdef WORDS_BIGENDIAN
	for (i = 0; i < Idea_keyLen; i++)
		key->Idea_Key[i] = byteswap16(userKey[i]);
# else
	for (i = 0; i < Idea_keyLen; i++)
		key->Idea_Key[i] = userKey[i];
# endif
#else
# ifdef WORDS_BIGENDIAN
	for (i = 0; i < Idea_userKeyLen; i++)
		key->Idea_Key[i] = byteswap16(userKey[i]);
# else
	for (i = 0; i < Idea_userKeyLen; i++)
		key->Idea_Key[i] = userKey[i];
# endif
	for (i = Idea_userKeyLen; i < Idea_keyLen; i++)
		if ((i & 7) < 6)
			key->Idea_Key[i] =
			    (key->Idea_Key[i - 7] & 127) << 9 | key->
			    Idea_Key[i - 6] >> 7;
		else if ((i & 7) == 6)
			key->Idea_Key[i] =
			    (key->Idea_Key[i - 7] & 127) << 9 | key->
			    Idea_Key[i - 14] >> 7;
		else
			key->Idea_Key[i] =
			    (key->Idea_Key[i - 15] & 127) << 9 | key->
			    Idea_Key[i - 14] >> 7;
#endif

	_mcrypt_Idea_InvertKey(key);

	return 0;
}				/* Idea_ExpandUserKey */

/******************************************************************************/


int _mcrypt_get_size()
{
	return sizeof(IDEA_KEY);
}

int _mcrypt_get_block_size()
{
	return 8;
}

int _is_block_algorithm()
{
	return 1;
}

int _mcrypt_get_key_size()
{
	return 16;
}

char *_mcrypt_get_algorithms_name()
{
	return "IDEA";
}

#define CIPHER "3223edc0f33ba078"

int _mcrypt_self_test()
{
	char *keyword;
	unsigned char *plaintext;
	unsigned char *ciphertext;
	int blocksize = _mcrypt_get_block_size(), j;
	void *key;
	unsigned char cipher_tmp[200];

	keyword = calloc(1, _mcrypt_get_key_size());
	for (j = 0; j < _mcrypt_get_key_size(); j++) {
		keyword[j] = ((j * 2 + 10) % 256);
	}
	ciphertext = calloc(1, blocksize);
	plaintext = calloc(1, blocksize);
	for (j = 0; j < blocksize; j++) {
		plaintext[j] = j % 256;
	}
	key = malloc(_mcrypt_get_size());
	memcpy(ciphertext, plaintext, blocksize);

	_mcrypt_set_key(key, (void *) keyword, _mcrypt_get_key_size());
	_mcrypt_encrypt(key, (void *) ciphertext);

	for (j = 0; j < blocksize; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
			ciphertext[j]);
	}

	if (strcmp((char *) cipher_tmp, CIPHER) != 0) {
		printf("failed compatibility\n");
		printf("Expected: %s\nGot: %s\n", CIPHER,
		       (char *) cipher_tmp);
		return -1;
	}
	_mcrypt_decrypt(key, (void *) ciphertext);

	for (j = 0; j < blocksize; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
			ciphertext[j]);
	}
	if (memcmp(ciphertext, plaintext, _mcrypt_get_block_size()) != 0) {
		printf("Got: %s\n", (char *) cipher_tmp);
		printf("failed internally\n");
		return -1;
	}
	return 0;
}

word32 _mcrypt_algorithm_version()
{
	return 20010701;
}
static const int key_sizes[] = { 16 };
const int *_mcrypt_get_supported_key_sizes(int *len)
{
	*len = sizeof(key_sizes)/sizeof(int);
	return key_sizes;
}
