#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <cstddef>
#include <cstdlib>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>
#include "watchlist.hpp"

using namespace std;
using json = nlohmann::json; // For JSON file serialization/deserialization

#define BUFFER_SIZE 4096 // Page size (4KB)

// Generate hash for a file
string generateChecksum(const string &path)
{
  FILE *fp;
  const EVP_MD *md;
  EVP_MD_CTX *mdctx;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLength;
  vector<unsigned char> buffer(BUFFER_SIZE);
  size_t bytes;
  string finalHash;

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
    char tmp[3];
    snprintf(tmp, sizeof(tmp), "%02x", hash[i]);
    finalHash += tmp;
  }

  return finalHash;
}

// Recursive directory traversal
void directoryTraversal(const string &path, json &output)
{
  DIR *dir;
  struct dirent *dirent;

  if (!(dir = opendir(path.c_str())))
    return;

  // Read directory
  while ((dirent = readdir(dir)) != nullptr)
  {
    string currPath;
    currPath = path + "/" + dirent->d_name;

    if (dirent->d_type == DT_DIR)
    {
      // Skip '.' and '..'
      if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
        continue;

      // Go inside this directory, list its contents as well
      directoryTraversal(currPath, output);
    }

    // Generate hash
    string hash = generateChecksum(currPath);
    output.push_back({{"path", currPath},
                      {"hash", hash}});
  }
  closedir(dir);
}

// Generation of initial hash database
void initialSetup()
{
  json hashFile = json::array();

  // for (const auto &directory : watchlist)
  //{
  //   directoryTraversal(directory);
  // }
  directoryTraversal("/home/userlinux/", hashFile);

  ofstream outFile("/home/userlinux/hashes.json");
  outFile << setw(4) << hashFile << endl;
  outFile.close();
}

void initializeDaemon()
{
  pid_t pid;

  // First fork
  pid = fork();

  if (pid < 0)
    exit(EXIT_FAILURE);

  if (pid > 0)
    exit(EXIT_SUCCESS);

  if (setsid() < 0)
    exit(EXIT_FAILURE);

  // Second fork
  pid = fork();

  if (pid < 0)
    exit(EXIT_FAILURE);

  if (pid > 0)
    exit(EXIT_SUCCESS);

  umask(0);
  chdir("/");

  int x;
  for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--)
  {
    close(x);
  }
}

int main()
{
  pid_t pidA = fork();
  if (pidA == 0)
  {
    initializeDaemon();
    initialSetup();
  }

  return (0);
}