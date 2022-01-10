//
// Created by dev on 12/21/21.
//

#ifndef SECRYPT_LSECUTIL_H
#define SECRYPT_LSECUTIL_H

#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif
off_t get_file_size(char *file_path);
ssize_t read_file_to_buffer(char *file_path, unsigned char **buffer);
void dump_buffer(const void *data, size_t size, char *dump_file);
void xor_buffer( unsigned char **buffer, unsigned long bufferSize, unsigned char key );
void uxor_buffer( unsigned char **buffer, unsigned long bufferSize, unsigned char key );
unsigned int leftRotate(unsigned int n, int d);
unsigned int rightRotate(unsigned int n, int d);
void xKey2Buf( char * key, unsigned long ** out);

#endif //SECRYPT_LSECUTIL_H
