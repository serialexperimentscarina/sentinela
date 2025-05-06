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
#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include "watchlist.hpp"

using namespace std;
using json = nlohmann::json; // for JSON file serialization/deserialization

#define BUFFER_SIZE 4096 // page size (4KB)
#define BLOCK_SIZE 16    // block size for AES-GCM (16 bytes = 128 bits)

// encrypt and save JSON file
void encryptJSON(const json &jsonFile, const vector<unsigned char> &key, const vector<unsigned char> &iv, vector<unsigned char> &tag)
{
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *cipherctx;
  int cipherLength, totalCipherLength = 0;

  string jsonText = jsonFile.dump();
  const unsigned char *jsonData = reinterpret_cast<const unsigned char *>(jsonText.data());
  int jsonLength = static_cast<int>(jsonText.size());

  // initialize encryption
  cipher = EVP_aes_256_gcm();
  cipherctx = EVP_CIPHER_CTX_new();

  EVP_EncryptInit_ex(cipherctx, cipher, NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(cipherctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
  EVP_EncryptInit_ex(cipherctx, NULL, NULL, key.data(), iv.data());

  // encrypt
  vector<unsigned char> cipherText(jsonLength + BLOCK_SIZE);
  EVP_EncryptUpdate(cipherctx, cipherText.data(), &cipherLength, jsonData, jsonLength);
  totalCipherLength += cipherLength;
  EVP_EncryptFinal_ex(cipherctx, cipherText.data() + cipherLength, &cipherLength);
  totalCipherLength += cipherLength;

  // wite to file
  ofstream out("/home/userlinux/hashes.enc", ios::binary);
  out.write(reinterpret_cast<char *>(cipherText.data()), totalCipherLength);

  // save tag
  EVP_CIPHER_CTX_ctrl(cipherctx, EVP_CTRL_GCM_GET_TAG, BLOCK_SIZE, tag.data());

  // free context
  EVP_CIPHER_CTX_free(cipherctx);
}

// decrypt JSON & save contents to a temporary file
void decryptJSON(const vector<unsigned char> &key, const vector<unsigned char> &iv, const vector<unsigned char> &tag)
{
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *cipherctx;

  // initialize decryption
  cipher = EVP_aes_256_gcm();
  cipherctx = EVP_CIPHER_CTX_new();

  EVP_DecryptInit_ex(cipherctx, cipher, NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(cipherctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
  EVP_DecryptInit_ex(cipherctx, NULL, NULL, key.data(), iv.data());

  vector<unsigned char> buffer(BUFFER_SIZE);
  vector<unsigned char> decrypt(BUFFER_SIZE + 16);
  int outLength, inLength;

  // open encrypted file
  ifstream in("/home/userlinux/hashes.enc", ios::binary);

  // open temporary decrypted file for reading
  ofstream out("/tmp/hashes.json", ios::binary);

  // read file and decrypt, block by block
  while (in.read(reinterpret_cast<char *>(buffer.data()), BUFFER_SIZE) || in.gcount())
  {
    inLength = static_cast<int>(in.gcount());
    EVP_DecryptUpdate(cipherctx, decrypt.data(), &outLength, buffer.data(), inLength);
    out.write(reinterpret_cast<char *>(decrypt.data()), outLength);
  }

  // authentication tag
  EVP_CIPHER_CTX_ctrl(cipherctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<unsigned char *>(tag.data()));
  EVP_DecryptFinal_ex(cipherctx, decrypt.data(), &outLength);

  // clean context
  EVP_CIPHER_CTX_free(cipherctx);
}

// generate hash for a file
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

  // open file and context
  fp = fopen(path.c_str(), "rb");
  md = EVP_get_digestbyname("sha256");
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);

  // hash
  while ((bytes = fread(buffer.data(), 1, BUFFER_SIZE, fp)) > 0)
  {
    EVP_DigestUpdate(mdctx, buffer.data(), bytes);
  }

  // close file and free context
  fclose(fp);
  EVP_DigestFinal_ex(mdctx, hash, &hashLength);
  EVP_MD_CTX_free(mdctx);

  // write to finalHash
  for (int i = 0; i < hashLength; ++i)
  {
    char tmp[3];
    snprintf(tmp, sizeof(tmp), "%02x", hash[i]);
    finalHash += tmp;
  }

  return finalHash;
}

// recursive directory traversal
void directoryTraversal(const string &path, json &output)
{
  DIR *dir;
  struct dirent *dirent;

  if (!(dir = opendir(path.c_str())))
    return;

  // read directory
  while ((dirent = readdir(dir)) != nullptr)
  {
    string currPath;
    currPath = path + "/" + dirent->d_name;

    if (dirent->d_type == DT_DIR)
    {
      // skip '.' and '..'
      if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
        continue;

      // go inside this directory, list its contents as well
      directoryTraversal(currPath, output);
    }

    // generate hash
    string hash = generateChecksum(currPath);
    output.push_back({{"path", currPath},
                      {"hash", hash}});
  }
  closedir(dir);
}

// generation of initial hash database
void initialSetup(const vector<unsigned char> &key, const vector<unsigned char> &iv, vector<unsigned char> &tag)
{
  json hashFile = json::array();

  // for (const auto &directory : watchlist)
  //{
  //   directoryTraversal(directory);
  // }
  directoryTraversal("/home/userlinux/sentinela/src/", hashFile);

  // encrypt and save JSON
  encryptJSON(hashFile, key, iv, tag);
}

void initializeDaemon()
{
  pid_t pid;

  // first fork
  pid = fork();

  if (pid < 0)
    exit(EXIT_FAILURE);

  if (pid > 0)
    exit(EXIT_SUCCESS);

  if (setsid() < 0)
    exit(EXIT_FAILURE);

  // second fork
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

void monitor(const vector<unsigned char> &key, const vector<unsigned char> &iv, vector<unsigned char> &tag)
{
  ofstream log("/tmp/sentinela.log", ios::app);

  while (true)
  {
    sleep(60); // sleep for a minute

    // decrypt file
    decryptJSON(key, iv, tag);

    // read decrypted file
    ifstream inFile("/tmp/hashes.json");
    json input;
    inFile >> input;
    time_t now = time(nullptr);

    // interate through each path on the JSON
    for (const auto &item : input)
    {
      string path = item["path"];
      string hash = item["hash"];

      // regenerate hash
      string currHash = generateChecksum(path);

      // compare hashes
      if (hash == currHash)
      {
        log << "path: " << path << " (hashes are the same) , at: " << ctime(&now);
      }
      else
      {
        log << "path: " << path << " (HASHES ARE DIFFERENT) , at: " << ctime(&now);
      }

      log.flush();
    }

    // delete decrypted file
    remove("/tmp/hashes.json");
  }
}

int main()
{
  vector<unsigned char> key(32); // key for encryption (32 bytes = 256 bits for AES-256)
  vector<unsigned char> iv(12);  // iv for encryption (12 bytes = 96 bits for AES-GCM)
  vector<unsigned char> tag(16); // tag for encryption (16 bytes = 128 bits for AES-GCM)

  // randomize key and iv
  RAND_bytes(key.data(), key.size());
  RAND_bytes(iv.data(), iv.size());

  pid_t pidSetup = fork();
  if (pidSetup == 0)
  {
    initializeDaemon();
    initialSetup(key, iv, tag);
    exit(EXIT_SUCCESS);
  }

  pid_t pidMonitor = fork();
  if (pidMonitor == 0)
  {
    initializeDaemon();
    monitor(key, iv, tag);
    exit(EXIT_SUCCESS);
  }

  return (0);
}