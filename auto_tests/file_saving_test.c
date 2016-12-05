/* file_saving_test.c
 *
 * Small test for checking if obtaining savedata, saving it to disk and using
 * works correctly.
 *
 *  Copyright (C) 2016 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/tox.h"
#include "../toxencryptsave/toxencryptsave.h"

static const char *pphrase = "bar", *name = "foo";

void tse(void)
{
    Tox *t;
    struct Tox_Options to;
    uint8_t *clear, *cipher;
    off_t sz;
    FILE *f;
    TOX_ERR_ENCRYPTION eerr;

    tox_options_default(&to);
    t = tox_new(&to, NULL);

    tox_self_set_name(t, (uint8_t *)name, strlen((char *)name), NULL);

    f = fopen("save", "w");

    sz = tox_get_savedata_size(t);
    clear = malloc(sz);

    /*this function does not write any data at all*/
    tox_get_savedata(t, clear);

    sz += TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    cipher = malloc(sz);

    if (!tox_pass_encrypt(clear, sz - TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (uint8_t *)pphrase, strlen(pphrase), cipher,
                          &eerr)) {
        fprintf(stderr, "error: could not encrypt, error code %d\n", eerr);
        exit(4);
    }

    fwrite(cipher, sz, sizeof(*cipher), f);

    free(cipher);
    free(clear);
    fclose(f);
    tox_kill(t);
}

void tsd(void)
{
    uint8_t readname[TOX_MAX_NAME_LENGTH];
    uint8_t *clear, * cipher;
    int sz;
    FILE *f;
    Tox *t;
    struct Tox_Options to;
    TOX_ERR_NEW err;
    TOX_ERR_DECRYPTION derr;

    f = fopen("save", "r");
    sz = fseek(f, 0, SEEK_END);
    fseek(f, 0, SEEK_SET);

    cipher = malloc(sz);
    clear = malloc(sz - TOX_PASS_ENCRYPTION_EXTRA_LENGTH);
    fgets((char *)cipher, sz, f);

    if (!tox_pass_decrypt(cipher, sz, (uint8_t *)pphrase, strlen(pphrase), clear, &derr)) {
        fprintf(stderr, "error: could not decrypt, error code %d\n", derr);
        exit(3);
    }

    tox_options_default(&to);
    to.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    to.savedata_data = clear;

    if ((t = tox_new(&to, &err)) == NULL) {
        fprintf(stderr, "error: tox_new returned the error value %d\n", err);
        exit(1);
    }

    tox_self_get_name(t, readname);
    readname[tox_self_get_name_size(t)] = '\0';

    if (strcmp((char *)readname, name)) {
        fprintf(stderr, "error: name returned by tox_self_get_name does not match expected result\n");
        exit(2);
    }

    free(cipher);
    free(clear);
    fclose(f);
    tox_kill(t);
}

int main(void)
{
    tse();
    tsd();

    remove("save");

    return 0;
}

