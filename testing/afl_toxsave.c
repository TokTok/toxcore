#include <malloc.h>
#include <stdio.h>

#include "tox/tox.h"

int main( int argc, char** argv ) {
    if (argc != 2) {
        return -1;
    }

    FILE *fileptr;
    uint8_t *buffer;
    long filelen;

    fileptr = fopen(argv[1], "rb");  // Open the file in binary mode
    fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
    filelen = ftell(fileptr);             // Get the current byte offset in the file
    rewind(fileptr);                      // Jump back to the beginning of the file

    buffer = (uint8_t *)malloc((filelen)*sizeof(uint8_t)); // Enough memory for file
    fread(buffer, filelen, 1, fileptr); // Read in the entire file
    fclose(fileptr); // Close the file

    TOX_ERR_OPTIONS_NEW error_options = 0;

    struct Tox_Options* tox_options = tox_options_new(&error_options);
    if (error_options != TOX_ERR_NEW_OK) {
        free(buffer);
        return -1;
    }

    tox_options_set_savedata_data(tox_options, buffer, filelen);
    tox_options_set_savedata_type(tox_options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    TOX_ERR_NEW error_new = 0;
    Tox* tox = tox_new(tox_options, &error_new);

    if (tox == NULL || error_new != TOX_ERR_NEW_OK) {
        free(buffer);
        return -1;
    }

    tox_kill(tox);
    free(buffer);

    return 0;
}
