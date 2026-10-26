
int FUN_18016a8a0(longlong param_1,undefined8 param_2,undefined8 param_3,int param_4,
                 undefined8 param_5,uint param_6,undefined8 *param_7)

{
  uint uVar1;
  undefined8 *puVar2;
  char cVar3;
  int iVar4;
  longlong lVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint *puVar9;
  
  uVar8 = 0;
  *param_7 = 0;
  cVar3 = nocrt_strlen(param_3);
  puVar2 = *(undefined8 **)(param_1 + 0x10);
  while( true ) {
    if (puVar2 == (undefined8 *)0x0) {
      return -0x4e;
    }
    if ((*(char *)((longlong)puVar2 + 0xbc) == cVar3) &&
       (iVar4 = nocrt_memcmp((longlong)puVar2 + 0xbd,param_3,cVar3), iVar4 == 0)) break;
    puVar2 = (undefined8 *)*puVar2;
  }
  if (((param_4 != 2) && (param_4 != 5)) &&
     ((*(int *)(puVar2 + 0x28) != param_4 ||
      (iVar4 = nocrt_strcmp((longlong)puVar2 + 0x144,param_5), iVar4 != 0)))) {
    lVar5 = RTLogRelGetDefaultInstanceEx(0x17b0010);
    if (lVar5 != 0) {
      RTLogLoggerEx(lVar5,0x10,0x17b,
                    "intnetR0OpenNetwork failed. rc=%Rrc pCur->szTrunk=%s pszTrunk=%s pCur->enmTrunkType=%d enmTrunkType=%d\n"
                    ,0xfffff1ed,(longlong)puVar2 + 0x144,param_5,*(undefined4 *)(puVar2 + 0x28),
                    param_4);
      return -0xe13;
    }
    return -0xe13;
  }
  uVar1 = *(uint *)(puVar2 + 0x16);
  if (((uVar1 ^ param_6) & 1) != 0) {
    return -0xe14;
  }
  if ((param_6 & 2) != 0) {
    puVar9 = &DAT_1801a78dc;
    uVar6 = uVar8;
    do {
      uVar7 = *puVar9 & param_6;
      if ((uVar7 != 0) && (uVar7 != (*puVar9 & uVar1))) {
        return -0xe14;
      }
      uVar6 = uVar6 + 1;
      puVar9 = puVar9 + 4;
    } while (uVar6 < 8);
  }
  if ((param_6 & 4) != 0) {
    puVar9 = &DAT_1801a78d8;
    do {
      if ((((param_6 & puVar9[-2]) != 0) && ((uVar1 & puVar9[-2]) == 0)) && ((*puVar9 & uVar1) != 0)
         ) {
        return -0xe14;
      }
      uVar8 = uVar8 + 1;
      puVar9 = puVar9 + 4;
    } while (uVar8 < 8);
  }
  iVar4 = SUPR0ObjAddRef(puVar2[0x12],param_2);
  if (iVar4 < 0) {
    if (iVar4 == -0x16) {
      iVar4 = -0x4e;
    }
  }
  else if (((*(byte *)(puVar2 + 0x16) & 0x20) == 0) ||
          (iVar4 = SUPR0ObjVerifyAccess(puVar2[0x12],param_2,(longlong)puVar2 + 0xbd), -1 < iVar4))
  {
    *param_7 = puVar2;
  }
  else {
    SUPR0ObjRelease(puVar2[0x12],param_2);
  }
  return iVar4;
}

