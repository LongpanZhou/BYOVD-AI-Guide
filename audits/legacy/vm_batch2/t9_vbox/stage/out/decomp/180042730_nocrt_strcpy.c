
char * nocrt_strcpy(char *param_1,char *param_2)

{
  char cVar1;
  char *pcVar2;
  
                    /* 0x42730  1634  nocrt_strcpy */
  pcVar2 = param_1;
  for (; (((cVar1 = *param_2, *pcVar2 = cVar1, cVar1 != '\0' &&
           (cVar1 = param_2[1], pcVar2[1] = cVar1, cVar1 != '\0')) &&
          (cVar1 = param_2[2], pcVar2[2] = cVar1, cVar1 != '\0')) &&
         (cVar1 = param_2[3], pcVar2[3] = cVar1, cVar1 != '\0')); param_2 = param_2 + 4) {
    pcVar2 = pcVar2 + 4;
  }
  return param_1;
}

