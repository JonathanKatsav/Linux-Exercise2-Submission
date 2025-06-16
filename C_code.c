
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>

#include "mta_rand.h"
#include "mta_crypt.h"

static int threadid = 0;
static unsigned int numOfDecrypters = 0;
static unsigned int passwordLen = 0;
static unsigned int keyLen = 0;
static unsigned int timeoutGiven = 0;
static bool         timeCon = false;

static char* encryptedData = NULL;
static unsigned int encryptedDataLength = 0;
static char* givenPassword = NULL;
static char* givenKey = NULL;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  encryptedPassNewCond    = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  foundCond  = PTHREAD_COND_INITIALIZER;

static unsigned long generation = 0;
static bool          found = false;
static unsigned long generationFoundIn = 0;



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void* decrypter_thread(void *arg);
void* encrypter_thread(void *arg);
void getInputFromUser(int argc, char** argv);
bool CheckFollowingARG(int i, int argc, const char *arg);
void inPutCheck(int argc, char** argv);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv) {

    getInputFromUser(argc, argv);

    keyLen = (passwordLen / 8);
    
    givenPassword    = malloc(passwordLen);
    encryptedData    = malloc(passwordLen);

    givenKey    = malloc(passwordLen + 1);
    
    givenKey[passwordLen] = '\0';

    if (MTA_crypt_init() != MTA_CRYPT_RET_OK) {
        fprintf(stderr, "MTA_crypt_init() failed\n");
        exit(EXIT_FAILURE);
    }

    pthread_t *dtids = calloc(numOfDecrypters, sizeof(pthread_t));
    for (unsigned int i = 0; i < numOfDecrypters; i++) {
        if (pthread_create(&dtids[i], NULL, decrypter_thread, NULL) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
        pthread_detach(dtids[i]);
    }
    pthread_t enc;

    if (pthread_create(&enc, NULL, encrypter_thread, NULL) != 0) {
        perror("pthread_create encrypter");
        exit(EXIT_FAILURE);
    }
    pthread_join(enc, NULL);

    return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// input from user functions
void getInputFromUser(int argc, char** argv) {

    inPutCheck(argc, argv);
    if (numOfDecrypters == 0) {
        fprintf(stderr, "Missing num of decrypters\n");
        
        exit(EXIT_FAILURE);
    }
    if (passwordLen == 0){
        fprintf(stderr,"Error: password length must be multiple of 8\n");
        exit(EXIT_FAILURE);
    }
    if (passwordLen % 8 != 0) {
        fprintf(stderr, "Error: password length must be multiple of 8\n");
        exit(EXIT_FAILURE);
    }
}

bool CheckFollowingARG(int i, int argc, const char *arg) {
    if (i+1 >= argc) {
            fprintf(stderr, "Error: %s needs an argument\n", arg);
            return true;
        }
    return false;
}

void inPutCheck(int argc, char** argv){
    for (int i = 1; i < argc; i++) {

    char* arg = argv[i];

    if (strcmp(arg, "-n") == 0 || strcmp(arg, "--num-of-decrypters") == 0) {
        if (CheckFollowingARG(i, argc, arg)) {
            exit(EXIT_FAILURE);
        }
        numOfDecrypters = strtoul(argv[++i], NULL, 10);
    }
    else if (strcmp(arg, "-l") == 0 || strcmp(arg, "--password-length") == 0) {
        if (CheckFollowingARG(i, argc, arg)) {
            exit(EXIT_FAILURE);
        }
        passwordLen = strtoul(argv[++i], NULL, 10);
    }
    else if (strcmp(arg, "-t") == 0 || strcmp(arg, "--timeout") == 0) {
        if (CheckFollowingARG(i, argc, arg)) {
            exit(EXIT_FAILURE);
        }
        timeCon = true;
        timeoutGiven = strtoul(argv[++i], NULL, 10);
    }
    else {
        fprintf(stderr, "Unknown option: %s\n", arg);
        exit(EXIT_FAILURE);
    }
}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// "workers" functions
void* encrypter_thread(void *arg) {
    MTA_CRYPT_RET_STATUS cr;
    while (1) {
        int count = 0;
        while (count < passwordLen){
            givenPassword[count] = MTA_get_rand_char();
            if (isprint((unsigned char)givenPassword[count])){
                count++;
                givenPassword[count] == '\0';
                }
        }

        MTA_get_rand_data(givenKey, keyLen);
        
        cr = MTA_encrypt(
            givenKey, keyLen,
            givenPassword, passwordLen,
            encryptedData, &encryptedDataLength
        );
        if (cr != MTA_CRYPT_RET_OK) {
            fprintf(stderr, "Encryption failed (%d)\n", cr);
            exit(EXIT_FAILURE);
        }
        time_t ts = time(NULL);
        printf("%ld [SERVER] [INFO] New password generated: %.*s, key: %.*s\n", ts, passwordLen, givenPassword, keyLen, givenKey);


        pthread_mutex_lock(&mutex);
        generation++;
        found = false;
        pthread_cond_broadcast(&encryptedPassNewCond);

        if (!timeCon) {
            while (!found) {
                pthread_cond_wait(&foundCond, &mutex);
            }
        } else {
            pthread_mutex_unlock(&mutex);
            time_t start = time(NULL);
            while (!found && (time(NULL) - start) < timeoutGiven) {
                sleep(1);
            }
            pthread_mutex_lock(&mutex);
        }

        if (found && generationFoundIn == generation) {
            printf("Round %lu: password cracked: \"%.*s\"\n",
                   generation, passwordLen, givenKey);
            break;
        } else {
            time_t ts = time(NULL);
            printf(
                "%ld [SERVER] [ERROR] No password received during the configured timeout period (%lu seconds), regenerating password\n",
                ts,
                timeoutGiven
            );

        }
        pthread_mutex_unlock(&mutex);

    }
    return NULL;
}

void* decrypter_thread(void *arg) {
    int id = threadid++;
    unsigned long ThreadGen = 0;
    char* passGuess = malloc(passwordLen);
    char* candidateKey = malloc(keyLen);
    unsigned int passGuessLen;
    if (!passGuess || !candidateKey) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    while (1) {
        pthread_mutex_lock(&mutex);
        while (generation == ThreadGen)
            pthread_cond_wait(&encryptedPassNewCond, &mutex);
        ThreadGen = generation;
        pthread_mutex_unlock(&mutex);

        while (1) {
            pthread_mutex_lock(&mutex);
            if (generation != ThreadGen || found) {
                pthread_mutex_unlock(&mutex);
                break;
            }
            pthread_mutex_unlock(&mutex);

            MTA_get_rand_data(candidateKey, keyLen);

            if (MTA_decrypt(candidateKey, keyLen,
                            encryptedData, encryptedDataLength,
                            passGuess, &passGuessLen)
                != MTA_CRYPT_RET_OK){
                continue;
            }
        
            if (passGuessLen != passwordLen)
                continue;

            bool ok = true;
            for (unsigned int i = 0; i < passwordLen; i++) {
                if (!isprint((unsigned char)passGuess[i])) {
                    ok = false; break;
                }
            }
            if (!ok) continue;

            time_t ts = time(NULL);
            printf("%ld [CLIENT #%d] [INFO] After decryption(%.*s), key guessed(%c), sending to server after %lu iterations\n",
                ts,
                threadid,              
                passwordLen, passGuess,
                passGuess[keyLen - 1],
                ThreadGen);

            pthread_mutex_lock(&mutex);
            if (!found && generation == ThreadGen) {
                found = true;
                generationFoundIn = ThreadGen;
                memcpy(givenKey, passGuess, passwordLen);
                pthread_cond_signal(&foundCond);
            }
            pthread_mutex_unlock(&mutex);
            break;
        }
    }

    free(passGuess);
    free(candidateKey);
    return NULL;
}