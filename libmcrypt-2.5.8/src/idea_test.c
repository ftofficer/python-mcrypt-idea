/*
 *    Copyright (C) 1998,1999,2000,2002 Nikos Mavroyanopoulos
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "../include/mutils/mcrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Prints plaintext and ciphertext in hex for all the algorithms */

#define ALGORITHMS_DIR "../modules/algorithms/.libs"
#define MODES_DIR "../modules/modes/.libs"
/* #define ALGORITHMS_DIR NULL
 * #define MODES_DIR NULL
 */
#define TEXT "a small text, just to test the implementation"

int main()
{
	MCRYPT td, td2;
	int i, t, imax;
	int j, jmax, ivsize;
	int x = 0, siz;
	char *text;
	unsigned char *IV;
	unsigned char *key;
	int keysize;
	
    td = mcrypt_module_open("idea", ALGORITHMS_DIR, "cbc", MODES_DIR);
    td2 = mcrypt_module_open("idea", ALGORITHMS_DIR, "cbc", MODES_DIR);

    if (td != MCRYPT_FAILED && td2 != MCRYPT_FAILED) {
        fprintf(stderr, "Created IDEA cipher.\n");

        keysize = mcrypt_enc_get_key_size(td);
        fprintf(stderr, "Cipher key size %d.\n", keysize);

        key = calloc(1, keysize);
        if (key==NULL) exit(1);
					
        for (t=0;t<keysize;t++)
            key[t] = (t % 255) + 13;
					
        ivsize = mcrypt_enc_get_iv_size(td);
        fprintf(stderr, "IV size %d.\n", ivsize);
        if (ivsize>0) {
            IV = calloc( 1, ivsize);
            if (IV==NULL) exit(1);
            for (t=0;t<ivsize;t++)
                IV[t] = (t*2 % 255) + 15;
        }

        if (mcrypt_generic_init( td, key, keysize, IV) < 0) {
            fprintf(stderr, "Failed to Initialize algorithm!\n");
            return -1;
        }

        if (mcrypt_enc_is_block_mode(td)!=0)
            siz = (strlen(TEXT) / mcrypt_enc_get_block_size(td))*mcrypt_enc_get_block_size(td);
        else siz = strlen(TEXT);

        text = calloc( 1, siz);
        if (text==NULL) exit(1);
					
        memmove( text, TEXT, siz);

        mcrypt_generic( td, text, siz);

        if (mcrypt_generic_init( td2, key, keysize, IV) < 0) {
            fprintf(stderr, "Failed to Initialize algorithm!\n");
            return -1;
        }

        mdecrypt_generic( td2, text, siz);
        if ( memcmp( text, TEXT, siz) == 0) {
            printf( "   %s: ok\n", "cbc");
        } else {
            printf( "   %s: failed\n", "cbc");
            x=1;
        }

        mcrypt_generic_deinit(td);
        mcrypt_generic_deinit(td2);
        mcrypt_module_close(td);
        mcrypt_module_close(td2);
        free(text);
        free(key);
        if (ivsize>0) free(IV);
    }

    return 0;
}
