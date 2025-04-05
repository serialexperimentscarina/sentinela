#include <dirent.h>
#include <stdio.h>
#include "watchlist.h"

int main()
{
  DIR *d;
  struct dirent *dir;

  for (int i = 0; i < 9; i++)
  {
    d = opendir(watchlist[i]);
    if (d)
    {
      while ((dir = readdir(d)) != NULL)
      {
        printf("%s\n", dir->d_name);
      }
      closedir(d);
    }
  }

  return (0);
}
