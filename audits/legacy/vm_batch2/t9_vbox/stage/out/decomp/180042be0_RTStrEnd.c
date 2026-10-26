
char * RTStrEnd(char *param_1,longlong param_2)

{
  char *pcVar1;
  bool bVar2;
  
                    /* 0x42be0  494  RTStrEnd */
  if (param_2 != 0) {
    bVar2 = true;
    do {
      pcVar1 = param_1;
      if (param_2 == 0) break;
      param_2 = param_2 + -1;
      pcVar1 = param_1 + 1;
      bVar2 = *param_1 == '\0';
      param_1 = pcVar1;
    } while (!bVar2);
    if (bVar2) {
      return pcVar1 + -1;
    }
  }
  return (char *)0x0;
}

