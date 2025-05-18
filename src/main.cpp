#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
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
  ofstream log("/var/log/sentinela.log", ios::app);

  if (filesystem::create_directory("/var/lib/sentinela/"))
  {
    json hashFile = json::array();
    ofstream outFile("/var/lib/sentinela/hashes.json");

    for (const auto &directory : watchlist)
    {
      directoryTraversal(directory, hashFile);
      outFile << setw(4) << hashFile << endl;
    }
    outFile.close();

    time_t now = time(nullptr);
    log << "sucessfully hashed files, at: " << ctime(&now);
  }
  else
  {
    time_t now = time(nullptr);
    log << "could not create application directory, " << ctime(&now);
  }
  log.flush();
  log.close();
}

void monitor()
{
  // TODO: longer sleep on first execution so the first daemon has time to hash all files it needs to
  ofstream log("/var/log/sentinela.log", ios::app);
  while (true)
  {
    sleep(60); // Sleep for a minute

    ifstream inFile("/var/lib/sentinela/hashes.json");
    json input;
    inFile >> input;
    time_t now = time(nullptr);
    int discrepancies = 0;

    // Interate through each path on the JSON
    for (const auto &item : input)
    {
      string path = item["path"];
      string hash = item["hash"];

      // Regenerate hash
      string currHash = generateChecksum(path);

      // Compare hashes
      if (hash != currHash)
      {
        log << "Hash discrepancies found in: " << path << " at: " << ctime(&now);
        discrepancies++;
      }

      log.flush();
    }
    log << "Check concluded with " << discrepancies << " discrepancies found, at: " << ctime(&now);
    log.flush();
  }
}

bool isFirstExecution()
{
  filesystem::path dirPath("/var/lib/sentinela");
  return !(filesystem::exists(dirPath) && filesystem::is_directory(dirPath));
}

int main()
{
  if (isFirstExecution())
  {
    initialSetup();
  }

  monitor();

  return (0);
}