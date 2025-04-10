#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "watchlist.h"

#define BUFFER_SIZE 4096 // Page size (4KB)

// Generate hash for a file
void generate_checksum(const char *path)
{
  printf("%s (File)\n", path);
  FILE *fp;
  EVP_MD *md;
  EVP_MD_CTX *mdctx;
  unsigned char hash[EVP_MAX_MD_SIZE];
  int hash_length;
  unsigned char *buffer;
  unsigned int n_bytes;

  fp = fopen(path, "rb");
  md = EVP_get_digestbyname("sha256");
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);

  if (buffer = malloc(BUFFER_SIZE))
  {
    while ((n_bytes = fread(buffer, 1, BUFFER_SIZE, fp)) > 0)
    {
      EVP_DigestUpdate(mdctx, buffer, n_bytes);
    }

    fclose(fp);
    EVP_DigestFinal_ex(mdctx, hash, &hash_length);
    free(buffer);
    EVP_MD_CTX_free(mdctx);
  }
  else
  {
    printf("Something went wrong.\n");
    return;
  }

  for (int i = 0; i < hash_length; ++i)
  {
    printf("%02x", hash[i]);
  }

  printf("\n");
}

// Recursive directory traversal
void directory_traversal(const char *path)
{
  DIR *dir;
  struct dirent *dirent;

  if (!(dir = opendir(path)))
    return;

  // Read directory
  while ((dirent = readdir(dir)) != NULL)
  {
    char curr_path[PATH_MAX];
    snprintf(curr_path, sizeof(curr_path), "%s/%s", path, dirent->d_name);

    if (dirent->d_type == DT_DIR)
    {
      // Skip '.' and '..'
      if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
        continue;

      // Generate hash
      generate_checksum(curr_path);

      // Go inside this directory, list its contents as well
      directory_traversal(curr_path);
    }
    else
    {
      // Generate hash
      generate_checksum(curr_path);
    }
  }
  closedir(dir);
}

int main()
{
  for (int i = 0; i < 9; i++)
  {
    directory_traversal(watchlist[i]);
  }

  return (0);
}