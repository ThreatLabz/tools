# Decryption code for network communication

#include <Windows.h>
#include <stdio.h>
#define SEED_SIZE 32

VOID DeriveKey(BYTE seed[], BYTE key[]) {
    BYTE swapByte = 0;
    BYTE seedIndex = 0;
    BYTE calKeyIndex = 0;

    /* Initialize the key array */
    for (int i = 0; i < 256; i++) {
        key[i] = i;
    }

    /* Calculate XOR key */
    for (int currKeyIndex = 0; currKeyIndex < 256; currKeyIndex++) {
        calKeyIndex = seed[currKeyIndex % SEED_SIZE] + key[currKeyIndex] + calKeyIndex;
        swapByte = key[currKeyIndex];
        key[currKeyIndex] = key[calKeyIndex];
        key[calKeyIndex] = swapByte;
    }
 
    /* Print the derived XOR key */
    for (int k = 0; k < 256; k++) {
        printf("%02x ", key[k]);
    }
}

VOID Decrypt(BYTE data[], BYTE key[]) {
    BYTE XORKeySize = data[0];
    BYTE *XORKey = (BYTE*)data + sizeof(BYTE);
    UINT encryptedDataSize = data[sizeof(BYTE) + XORKeySize];
    BYTE *encryptedData = (BYTE*)data + (sizeof(BYTE) + XORKeySize + sizeof(UINT));
    BYTE *layer1DecryptedData = (BYTE*)malloc(encryptedDataSize);
    for (UINT dataIndex = 0; dataIndex < encryptedDataSize; dataIndex++) {
        layer1DecryptedData[dataIndex] = encryptedData[dataIndex] ^ XORKey[dataIndex % XORKeySize];

    }

    BYTE swapByte = 0;
    BYTE calKeyIndex = 0;
    BYTE finalKeyIndex = 0;

    for (UINT index = 1; index <= encryptedDataSize; index++) {
        calKeyIndex = key[index] + calKeyIndex;
        swapByte = key[index];
        key[index] = key[calKeyIndex];
        key[calKeyIndex] = swapByte;
        finalKeyIndex = key[index] + key[calKeyIndex];
        printf("%c ", layer1DecryptedData[index - 1] ^ key[finalKeyIndex]);

    }
}

int main() {
    BYTE key[256];
    BYTE seed[SEED_SIZE] = {  // Taken from configuration
        0xBD, 0xDE, 0x96, 0xD2, 0x9C, 0x68, 0xEE, 0x06, 0x49,
        0x64, 0xD1, 0xE5, 0x8A, 0x86, 0x05, 0x12, 0xB0, 0x9A,
        0x50, 0x00, 0x4E, 0xF2, 0xE4, 0x92, 0x5C, 0x76, 0xAB,
        0xFC, 0x90, 0x23, 0xDF, 0xC6
    };

    BYTE data[] = {  
    // Put Base64 decoded encrypted data here in HEX format
    };

    DeriveKey(seed, key);
    printf("\n\n");
    Decrypt(data, key);
    return 0;
}
