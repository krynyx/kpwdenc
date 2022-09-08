#ifndef KPWD_ENCRYPT
#define KPWD_ENCRYPT

#define ENCODE_LEVEL 4 //min is 2 and max is 8
#define MAX_KEY_SIZE 64
#define MAX_DATA_SIZE 64
#define MAX_DESC_SIZE 16
#define DATA_EXT_SIZE 4 //".dat"
#define DATA_EXT ".dat"
#define KEY_EXT_SIZE 4
#define KEY_EXT ".key"

typedef struct{
	unsigned char key[MAX_KEY_SIZE];
	short pwd_size;
}PRV_KEY;

typedef struct{
	unsigned char data[MAX_DATA_SIZE];
	unsigned char desc[MAX_DESC_SIZE];
}DATA;

#endif