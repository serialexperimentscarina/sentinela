#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <cstddef>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "watchlist.hpp"

#define BUFFER_SIZE 4096 // Page size (4KB)

// Generate hash for a file
void generateChecksum(const std::string &path)
{
  std::cout << path.c_str() << std::endl;

  FILE *fp;
  const EVP_MD *md;
  EVP_MD_CTX *mdctx;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLength;
  std::vector<unsigned char> buffer(BUFFER_SIZE);
  size_t bytes;

  fp = fopen(path.c_str(), "rb");
  md = EVP_get_digestbyname("sha256");
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);

  while ((bytes = fread(buffer.data(), 1, BUFFER_SIZE, fp)) > 0)
  {
    EVP_DigestUpdate(mdctx, buffer.data(), bytes);
  }

  fclose(fp);
  EVP_DigestFinal_ex(mdctx, hash, &hashLength);
  EVP_MD_CTX_free(mdctx);

  for (int i = 0; i < hashLength; ++i)
  {
    printf("%02x", hash[i]);
  }

  printf("\n");
}

// Recursive directory traversal
void directoryTraversal(const std::string &path)
{
  DIR *dir;
  struct dirent *dirent;

  if (!(dir = opendir(path.c_str())))
    return;

  // Read directory
  while ((dirent = readdir(dir)) != nullptr)
  {
    std::string currPath;
    currPath = path + "/" + dirent->d_name;

    if (dirent->d_type == DT_DIR)
    {
      // Skip '.' and '..'
      if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
        continue;

      // Generate hash
      generateChecksum(currPath);

      // Go inside this directory, list its contents as well
      directoryTraversal(currPath);
    }
    else
    {
      // Generate hash
      generateChecksum(currPath);
    }
  }
  closedir(dir);
}

int main()
{
  // for (const auto &directory : watchlist)
  //{
  //   directoryTraversal(directory);
  // }
  directoryTraversal(".");

  return (0);
}