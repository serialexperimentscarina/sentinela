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
#include "toml.hpp"

using namespace std;
using json = nlohmann::json; // For JSON file serialization/deserialization
namespace fs = filesystem;

#define BUFFER_SIZE 4096 // Page size (4KB)

// Generate hash for a file
string generateChecksumFile(const string &path)
{
  FILE *fp;
  const EVP_MD *md;
  EVP_MD_CTX *mdctx;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLength;
  vector<unsigned char> buffer(BUFFER_SIZE);
  size_t bytes;
  string finalHash;

  if (!(filesystem::exists(path)))
  {
    return "";
  }

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

// Generate hash for a folder
string generateChecksumFolder(const string &path)
{
  const EVP_MD *md;
  EVP_MD_CTX *mdctx;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLength;
  vector<string> fileVector;
  string finalHash;

  if (!(filesystem::exists(path)))
  {
    return "";
  }

  for (const auto &entry : fs::directory_iterator(path))
  {
    fileVector.push_back(entry.path().filename());
  }
  sort(fileVector.begin(), fileVector.end());
  string joinedFileVector = accumulate(fileVector.begin(), fileVector.end(), string{});

  md = EVP_get_digestbyname("sha256");
  mdctx = EVP_MD_CTX_new();

  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, joinedFileVector.data(), joinedFileVector.size());
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
void directoryTraversal(const string &path, json &output, int &filesHashed)
{
  if (!(filesystem::exists(path)))
  {
    return;
  }

  // Generate hash for directory
  string hash = generateChecksumFolder(path);
  output.push_back({{"path", path}, {"type", "folder"}, {"hash", hash}});
  filesHashed++;

  // Recursively traverse it
  for (const auto &entry : fs::directory_iterator(path))
  {
    if (entry.is_directory())
    {
      // Go inside this directory, list its contents as well
      directoryTraversal(entry.path().string(), output, filesHashed);
    }
    else
    {
      // Generate hash for files inside the directory
      string hash = generateChecksumFile(entry.path().string());
      output.push_back({{"path", entry.path().string()}, {"type", "file"}, {"hash", hash}});
      filesHashed++;
    }
  }
}

// Generation of initial hash database
void initialSetup(toml::table &config)
{
  ofstream log("/var/log/sentinela.log", ios::app);
  int filesHashed = 0;

  if (filesystem::create_directory("/var/lib/sentinela/"))
  {
    json hashFile = json::array();
    auto directories = config["watchlist"].as_array();

    for (const auto &directory : *directories)
    {
      if (auto path = directory.value<string>())
      {
        directoryTraversal(*path, hashFile, filesHashed);
      }
    }

    ofstream outFile("/var/lib/sentinela/hashes.json");
    outFile << hashFile.dump(4);
    outFile.close();

    time_t now = time(nullptr);
    log << "sucessfully hashed " << filesHashed << " files/directories, at: " << ctime(&now);
  }
  else
  {
    time_t now = time(nullptr);
    log << "could not create application directory, at: " << ctime(&now);
  }
  log.flush();
  log.close();
}

void monitor(toml::table &config)
{
  ofstream log("/var/log/sentinela.log", ios::app);
  auto checkInterval = config["checkInterval"].value<int>();
  int filesChecked;

  while (true)
  {
    sleep(*checkInterval); // Sleep for a minute
    filesChecked = 0;

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
      string type = item["type"];

      // Regenerate hash
      string currHash;
      if (type == "file")
      {
        currHash = generateChecksumFile(path);
      }
      else
      {
        currHash = generateChecksumFolder(path);
      }

      // Check for missing file or hash discrepancy
      if (currHash == "")
      {
        log << "File missing: " << path << " at: " << ctime(&now);
        discrepancies++;
      }
      else if (hash != currHash)
      {
        log << "Hash discrepancies found in: " << path << " at: " << ctime(&now);
        discrepancies++;
      }

      log.flush();
      filesChecked++;
    }
    log << "Check concluded with " << filesChecked << " files checked, " << discrepancies << " discrepancies found, at: " << ctime(&now);
    log.flush();
  }
}

bool isFirstExecution()
{
  filesystem::path dirPath("/var/lib/sentinela");
  return !(filesystem::exists(dirPath) && filesystem::is_directory(dirPath));
}

toml::table getConfigs()
{
  toml::table tbl;
  tbl = toml::parse_file("/etc/sentinela/config.toml");

  return tbl;
}

int main()
{
  // get configs
  toml::table configs;
  try
  {
    configs = getConfigs();
  }
  catch (const toml::parse_error &err)
  {
    ofstream log("/var/log/sentinela.log", ios::app);
    time_t now = time(nullptr);
    log << "could not read config file, at: " << ctime(&now);
    log.flush();
    log.close();

    return (1);
  }

  if (isFirstExecution())
  {
    initialSetup(configs);
  }

  monitor(configs);

  return (0);
}