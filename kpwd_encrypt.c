#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "kpwd_encrypt.h"

/*
	Esse algoritmo é um simples codificador de senhas
	que trabalha como um "embaralhador" de caracteres.
	
	Como funciona?
	
	Primeiro é gerado um array com caracteres aleatórios, chamado
	DATA. Depois é gerado um array denominado PRV_KEY, onde
	conterá os índices correspondentes aos dados originais
	armazenados em DATA.
	
	Basicamente PRV_KEY revela os índices de DATA que correspondem
	a senha. Sem ter conhecimento de PRV_KEY, isto é, saber seu
	valor, fica impossível descobrir a senha, visto que todos os
	caracteres de DATA podem fazer parte da senha.
	
	Recomendo o uso desse algoritmo para uma senha de até 32 dígitos.
	Sendo codificada uma senha com letras, números e caracteres especiais,
	fica impossível decifrá-la sem conhecer PRV_KEY, o qual revela os
	caracteres da senha.
	
	Como testar: gcc kpwd_encrypt.c -o kpwdenc
	
	Codificando:
		./kpwdenc e minhasenha meulembrete
		
	Decodificando:
		./kpwdenc d meulembrete.dat meulembrete.key
*/
void help();
void kpwdenc_encode(const char* pwd, const char* desc);
void kpwdenc_decode(const char* data_file, const char* key_file);
void _init_random_data(DATA *data);
void _init_random_key(PRV_KEY *k);
void _export_data(DATA *d);
void _export_key(PRV_KEY *k, const char *desc);
void _print_private_key(unsigned char *k);

int main(int argc, char **argv)
{
	
	//Check if the three arguments was informed
	if (argc != 4) {
		help();
	}
	
	if ((argv[1][0] != 'e') && (argv[1][0] != 'd')) {
		fprintf(stderr,"Error: unrecognized [%c] option\n", argv[1][0]);
		help();
	}
	
	if (argv[1][0] == 'e') {
		//encode
		kpwdenc_encode(argv[2], argv[3]);
	} else {
		//decode
		kpwdenc_decode(argv[2], argv[3]);

	}
}

void kpwdenc_encode(const char* pwd, const char* desc)
{
	DATA new_data;
	PRV_KEY new_key;
	
	memset(new_data.desc, 0x0, MAX_DESC_SIZE);
	memcpy(new_data.desc, desc, MAX_DESC_SIZE-1);
	memset(new_key.key, 0x0, MAX_KEY_SIZE);
	new_key.pwd_size = strlen(pwd);
	
	_init_random_data(&new_data);
	_init_random_key(&new_key);
	
	//ENCODE
	int ps = 0;
	for (int i = 0; i < MAX_KEY_SIZE && (ps < new_key.pwd_size); i++){

		if (new_key.key[i] == 1) {
			new_data.data[i] = pwd[ps++];
		}
	}
	
	new_data.data[MAX_DATA_SIZE-1] = '\0';
	_export_data(&new_data);
	_export_key(&new_key, desc);
}

void kpwdenc_decode(const char* data_file, const char* key_file)
{
	FILE *fd_key = fopen(key_file, "r+b");
	FILE *fd_data = fopen(data_file, "r+b");
	DATA d;
	PRV_KEY k;
	
	fread(&d, sizeof(DATA), 1, fd_data);
	fread(&k, sizeof(PRV_KEY), 1, fd_key);
	
	printf("PRIVATE KEY: ", k.key);
	_print_private_key(k.key);
	printf("PASSWORD SIZE: %d\n", k.pwd_size);
	printf("PASSWORD DESC: %s\n", d.desc);
	printf("ENCODED DATA: %s\n", d.data);
	printf("DECODED PASSWORD: ");
	
	for(int i = 0; i < MAX_KEY_SIZE; i++) {
		if (k.key[i] == 1) {
			printf("%c", d.data[i]);
		}
	}
	putchar('\n');
	fclose(fd_key);
	fclose(fd_data);
}

void help()
{
	printf("Usage:\n");
	printf("\tkpwdenc e <password> <description>\n");
	printf("\tkpwdenc d <kpwdenc.data> <kpwdenc.key>\n");
	printf("\n\n\te\t Used to encrypt a new password.\n");
	printf("\td\t Used to decode an existent encrypted password.\n");
	exit(EXIT_FAILURE);	
}

void _init_random_data(DATA *d)
{
	srand(time(NULL));
	memset(d->data, 0x0, MAX_DATA_SIZE);
	
	for (int i = 0; i < MAX_DATA_SIZE; i++){
		//use only alphanumeric/letters/especial characters
		d->data[i] = 48 + (rand() % 52);
	}
}

//this function generates a key based on bit value 1
void _init_random_key(PRV_KEY *k)
{
	int i, ps, r;
	
	ps = k->pwd_size;
	i = 0;
	
	while (ps > 0){
		r = rand() % ENCODE_LEVEL;
		if (r == 1 && (k->key[i] == 0)) {
			k->key[i] = 1;
			--ps;
		}
		if (++i == MAX_KEY_SIZE) {
			//zera o indice até achar a chave privada
			i = 0;
		}
	}
}

void _export_data(DATA *d)
{

	short desc_size = strlen(d->desc);
	char *filename;
	int f_size = sizeof(char) * (desc_size + DATA_EXT_SIZE + 1);
	
	filename = (char *)malloc(f_size);
	memset(filename, 0x0, f_size);
	memcpy(filename, d->desc, desc_size);
	memcpy(&filename[desc_size], DATA_EXT, DATA_EXT_SIZE);
	

	FILE *fd = fopen(filename, "w+b");
	fwrite(d, sizeof(DATA), 1, fd);
	fclose(fd);
}

void _export_key(PRV_KEY *k, const char *desc)
{
	short desc_size = strlen(desc);
	char *filename;
	int f_size = sizeof(char) * (desc_size + KEY_EXT_SIZE + 1);
	
	filename = (char *)malloc(f_size);
	memset(filename, 0x0, f_size);
	memcpy(filename, desc, desc_size);
	memcpy(&filename[desc_size], KEY_EXT, KEY_EXT_SIZE);
	
	FILE *fd = fopen(filename, "w+b");
	fwrite(k, sizeof(PRV_KEY), 1, fd);
	fclose(fd);
}

void _print_private_key(unsigned char *k)
{
	for(int i = 0; i < MAX_KEY_SIZE; i++) {
		printf("%x", k[i]);
	}
	putchar('\n');
}