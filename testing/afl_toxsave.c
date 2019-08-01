#include <malloc.h>
#include <stdio.h>

#include "tox/tox.h"

int main( int argc, char** argv ) {
    if (argc != 2) {
        return -1;
    }

    // determine file size
    FILE *fileptr = fopen(argv[1], "rb");
    fseek(fileptr, 0, SEEK_END);
    long filelen = ftell(fileptr);
    rewind(fileptr);

    // read file into buffer
    uint8_t *buffer = (uint8_t *)malloc(filelen * sizeof(uint8_t));
    fread(buffer, filelen, 1, fileptr);
    fclose(fileptr);

    TOX_ERR_OPTIONS_NEW error_options = 0;

    struct Tox_Options* tox_options = tox_options_new(&error_options);
    if (error_options != TOX_ERR_NEW_OK) {
        free(buffer);
        return -1;
    }

    // pass test data to Tox
    tox_options_set_savedata_data(tox_options, buffer, filelen);
    tox_options_set_savedata_type(tox_options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    TOX_ERR_NEW error_new = 0;
    Tox *tox = tox_new(tox_options, &error_new);

    if (tox == NULL || error_new != TOX_ERR_NEW_OK) {
        free(buffer);
        return -1;
    }

    tox_kill(tox);
    free(buffer);

    return 0;
}
