
int nocrt_strcmp(char *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  
  while( true ) {
                    /* 0x426d0  1633  nocrt_strcmp */
    cVar1 = *param_1;
    uVar2 = (uint)CONCAT11(*param_2,cVar1);
    if (cVar1 != *param_2) break;
    if (cVar1 == '\0') {
      return 0;
    }
    cVar1 = param_1[1];
    uVar2 = (uint)CONCAT11(param_2[1],cVar1);
    if (cVar1 != param_2[1]) break;
    if (cVar1 == '\0') {
      return 0;
    }
    cVar1 = param_1[2];
    uVar2 = (uint)CONCAT11(param_2[2],cVar1);
    if (cVar1 != param_2[2]) break;
    if (cVar1 == '\0') {
      return 0;
    }
    cVar1 = param_1[3];
    uVar2 = (uint)CONCAT11(param_2[3],cVar1);
    if (cVar1 != param_2[3]) break;
    if (cVar1 == '\0') {
      return 0;
    }
    param_1 = param_1 + 4;
    param_2 = param_2 + 4;
  }
  return (uVar2 & 0xff) - (uVar2 >> 8);
}

