#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <tox/tox.h>
#include <tox/toxencryptsave.h>

char* pphrase="bar", * name="foo";

void tse(void)
{
	Tox* t;
	struct Tox_Options to;
	uint8_t* clear, * cipher;
	off_t sz;
	int fd;
	TOX_ERR_ENCRYPTION eerr;

	tox_options_default(&to);
	t=tox_new(&to, NULL);

	tox_self_set_name(t, (uint8_t*)name, strlen((char*)name), NULL);

	fd = open("save", O_WRONLY | O_TRUNC | O_CREAT , 0666);

	sz = tox_get_savedata_size(t);
	clear = malloc(sz);

	/*this function does not write any data at all*/
	tox_get_savedata(t, clear);

	sz += TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
	cipher = malloc(sz);
	if(!tox_pass_encrypt(clear, sz - TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (uint8_t*)pphrase, strlen(pphrase), cipher, &eerr))
	{
		fprintf(stderr, "error: could not encrypt, error code %d\n", eerr);
		exit(4);
	}

	write(fd, cipher, sz);
	fsync(fd);

	free(cipher);
	free(clear);
	close(fd);
	tox_kill(t);
}

void tsd(void)
{
	uint8_t readname[TOX_MAX_NAME_LENGTH];
	uint8_t* clear, * cipher;
	off_t sz;
	int fd;
	Tox* t;
	struct Tox_Options to;
	TOX_ERR_NEW err;
	TOX_ERR_DECRYPTION derr;

	fd = open("save", O_RDONLY , 0666);
	sz = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	cipher = malloc(sz);
	clear = malloc(sz - TOX_PASS_ENCRYPTION_EXTRA_LENGTH);
	read(fd, cipher, sz);

	if(!tox_pass_decrypt(cipher, sz, (uint8_t*)pphrase, strlen(pphrase), clear, &derr))
	{
		fprintf(stderr, "error: could not decrypt, error code %d\n", derr);
		exit(3);
	}

	tox_options_default(&to);
	to.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
	to.savedata_data = clear;
	if((t = tox_new(&to, &err)) == NULL)
	{
		fprintf(stderr, "error: tox_new returned the error value %d\n", err);
		exit(1);
	}

	tox_self_get_name(t, readname);
	name[tox_self_get_name_size(t)] = '\0';

	if(strcmp((char*)readname, name))
	{
		fprintf(stderr, "error: name returned by tox_self_get_name does not match expected result\n");
		exit(2);
	}

	free(cipher);
	free(clear);
	close(fd);
	tox_kill(t);
}

int main(void)
{
	tse();
	tsd();

	return 0;
}

