
longlong nocrt_strlen(char *param_1)

{
  char cVar1;
  longlong lVar2;
  
                    /* 0x42bb0  1635  nocrt_strlen */
  lVar2 = -1;
  do {
    if (lVar2 == 0) break;
    lVar2 = lVar2 + -1;
    cVar1 = *param_1;
    param_1 = param_1 + 1;
  } while (cVar1 != '\0');
  return -2 - lVar2;
}

