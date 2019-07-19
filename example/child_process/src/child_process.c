#include <stdint.h>
#include <stdio.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int32_t main()
{
  int32_t lives = 60;

  while (--lives)
  {
    puts("Ah, ha, ha, ha, stayin' alive, stayin' alive");

    Sleep(1000);
  }

  return 0;
}