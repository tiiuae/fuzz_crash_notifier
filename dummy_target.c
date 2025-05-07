#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For exit

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        // perror("Failed to open input file"); // Fuzzers often try non-existent files
        return 1;
    }

    char buffer[100];
    size_t nread = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);

    if (nread > 0) {
        buffer[nread] = '\0'; // Null-terminate
        // printf("Read: %s\n", buffer); // Optional: for debugging target
        if (strncmp(buffer, "CRASH", 5) == 0) {
            fprintf(stderr, "Crashing as requested by input!\n");
            fflush(stderr); // Ensure message is printed before crash
            *((volatile int*)0) = 0; // Segfault
        }
    } else {
        // printf("Empty input or read error.\n"); // Optional
    }

    return 0;
}
