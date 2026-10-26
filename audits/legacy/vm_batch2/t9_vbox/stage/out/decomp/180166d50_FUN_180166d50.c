
void FUN_180166d50(longlong param_1,int param_2,longlong *param_3,undefined8 param_4)

{
  byte bVar1;
  char cVar2;
  longlong *plVar3;
  int iVar4;
  char cVar5;
  longlong lVar6;
  bool bVar7;
  
  lVar6 = (longlong)param_2 * 0x10 + param_1;
  bVar1 = *(byte *)(lVar6 + 0x70);
  cVar5 = *(char *)(lVar6 + 0x72);
  if (bVar1 != 0) {
    plVar3 = *(longlong **)(lVar6 + 0x68);
    if (cVar5 == '\x04') {
      if ((int)*plVar3 == (int)*param_3) {
        return;
      }
    }
    else if (cVar5 == '\n') {
      if ((*plVar3 == *param_3) && ((short)plVar3[1] == (short)param_3[1])) {
        return;
      }
    }
    else if (((cVar5 == '\x10') && (*plVar3 == *param_3)) && (plVar3[1] == param_3[1])) {
      return;
    }
    if ((1 < bVar1) &&
       (cVar2 = FUN_1801668c0((ulonglong)((uint)*(byte *)(lVar6 + 0x73) * (bVar1 - 1)) +
                              (longlong)plVar3,param_3), cVar2 != '\0')) {
      return;
    }
  }
  iVar4 = bVar1 - 2;
  plVar3 = *(longlong **)(lVar6 + 0x68);
  do {
    if (iVar4 < 1) {
      FUN_180166e80(param_1,param_2,param_3,param_4);
      return;
    }
    plVar3 = (longlong *)((longlong)plVar3 + (ulonglong)*(byte *)(lVar6 + 0x73));
    if (cVar5 == '\x04') {
      bVar7 = (int)*plVar3 == (int)*param_3;
LAB_180166e4c:
      if (bVar7) {
        return;
      }
    }
    else if (cVar5 == '\n') {
      if (*plVar3 == *param_3) {
        bVar7 = (short)plVar3[1] == (short)param_3[1];
        goto LAB_180166e4c;
      }
    }
    else if ((cVar5 == '\x10') && (*plVar3 == *param_3)) {
      bVar7 = plVar3[1] == param_3[1];
      goto LAB_180166e4c;
    }
    iVar4 = iVar4 + -1;
  } while( true );
}

