//
// Created by dev on 12/21/21.
//

#include "lsecutil.h"

/*Function to get file size*/
off_t get_file_size(char *fpath){

    struct stat st;
    if ( -1 == stat(fpath, &st) ) {
        err(EXIT_FAILURE, "stat() \"%s\" failed", fpath);
    }
    return st.st_size;
}

/*Function to read data from file into buffer*/
ssize_t read_file_to_buffer(char *fpath, unsigned char **buffer){

    ssize_t nread = 0;
    int fd;
    off_t fsize = 0;

    if ((fd = open(fpath, O_RDONLY)) < 0) {
        err(EXIT_FAILURE, "open() \"%s\" RW failed", fpath);
    }

    fsize = get_file_size(fpath);
    *buffer = calloc(fsize, sizeof (unsigned char));
    if ( NULL == *buffer){
        err(EXIT_FAILURE, "calloc() failed: %s for %ld bytes", fpath, fsize);
    }

    nread = read(fd, *buffer, fsize);
    printf("fd: %d file %s size %ld, read %ld\n", fd,  fpath, fsize, nread);
    if (nread < 0 || nread < fsize) {
        err(EXIT_FAILURE, "read() \"%s\" failed", fpath);
    }
    return nread;
}

/*Function to dump binary buffer to file (f*) */
size_t write_buffer_to_file(char* file_name, char ** data, u_int64_t sz){
    FILE *pFile = fopen(file_name, "wb");
    size_t n = -1;

    if (pFile != NULL) {
        n = fwrite(*data, sizeof(u_int8_t), sz, pFile );
    }else{
        err(EXIT_FAILURE, "fwrite \"%s\" failed", file_name);
    }
    fclose(pFile);
    return n;
}

/*Function to dump binary buffer to file*/
void dump_buffer(const void *data, size_t size, char *dump_file) {
    if (dump_file != NULL) {
        ssize_t nwritten = -1;
        int fd = -1;
        if ((fd = open(dump_file, O_RDWR|O_CREAT)) < 0) {
            err(EXIT_FAILURE, "open() \"%s\" RW failed", dump_file);
        }
        nwritten = write(fd, data, size);
        if (nwritten < 0 || nwritten < size) {
            err(EXIT_FAILURE, "write() \"%s\" failed", dump_file);
        }
        close(fd);
    }
}

/*Function to XOR buffer with additional bit shifting*/
void xor_buffer( unsigned char **buffer, unsigned long bufferSize, unsigned char key ){

    int i;
    for(i = 0;i < bufferSize;i++){

        (*buffer)[i] = leftRotate( (*buffer)[i] ^ key, 2);
        //(*buffer)[i] = (*buffer)[i] ^ key;
    }
}
/*Function to un-XOR buffer with additional bit shifting*/
void uxor_buffer( unsigned char **buffer, unsigned long bufferSize, unsigned char key ){

    int i;
    for(i = 0;i < bufferSize;i++){
        // (*buffer)[i] = (*buffer)[i] ^ key;
        (*buffer)[i] = rightRotate( (*buffer)[i], 2 ) ^ key;
    }
}

/*Function to left rotate n by d bits*/
unsigned int leftRotate(unsigned int n, int d)
{
    return (((n << d) & 0xFF) | (n >> (8-d)));
}

/*Function to right rotate n by d bits*/
unsigned int rightRotate(unsigned int n, int d)
{
    return (((n >> d) & 0xFF) | (n << (8-d)));
}

/*Function to insert char XOR key into ulong array */
void xKey2Buf( char * key, unsigned long ** out){
   *out = (unsigned long*) calloc(sizeof(unsigned char), 2);
    char *endptr = NULL;
    errno = 0;

    // Convert str key to long
    *out[0] = strtol(key, NULL, 16);
    if (errno != 0) {
        err(EXIT_FAILURE, "strtol() conversion of key %s", key);
    }

    if (endptr == key) {
        err(EXIT_FAILURE, "strtol(): no digits found %s", key);
    }
}