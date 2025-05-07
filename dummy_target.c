#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  FILE *fp = fopen(argv[1], "rb");
  if (!fp) {
    return 1;
  }

  char buffer[100];
  size_t nread = fread(buffer, 1, sizeof(buffer) - 1, fp);
  fclose(fp);

  if (nread > 0) {
    buffer[nread] = '\0';
    // printf("Read: %s\n", buffer);
    if (strncmp(buffer, "CRASH", 5) == 0) {
      fprintf(stderr, "Crashing as requested by input!\n");
      fflush(stderr);           // Ensure message is printed before crash
      *((volatile int *)0) = 0; // Segfault
    }
  } else {
    // printf("Empty input or read error.\n");
  }

  return 0;
}
