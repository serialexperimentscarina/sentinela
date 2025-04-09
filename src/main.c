#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include "watchlist.h"

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
    if (dirent->d_type == DT_DIR)
    {
      // Skip '.' and '..'
      if (strcmp(dirent->d_name, ".") == 0 || strcmp(dirent->d_name, "..") == 0)
        continue;

      printf("%s (Directory)\n", dirent->d_name);

      // Go inside this directory, list its contents as well
      char next_path[PATH_MAX];
      snprintf(next_path, sizeof(next_path), "%s/%s", path, dirent->d_name);
      directory_traversal(next_path);
    }
    else
    {
      printf("%s (File)\n", dirent->d_name);
    }
  }
  closedir(dir);
}

int main()
{

  // for (int i = 0; i < 9; i++)
  //{
  //   d = opendir(watchlist[i]);
  //   if (d)
  //   {
  //     while ((dir = readdir(d)) != NULL)
  //     {
  //       printf("%s\n", dir->d_name);
  //     }
  //     closedir(d);
  //   }
  // }

  return (0);
}