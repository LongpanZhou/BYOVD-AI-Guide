
int FUN_1801669d0(longlong param_1,undefined8 param_2,void *param_3,int param_4,undefined8 param_5,
                 uint param_6,undefined8 *param_7)

{
  byte bVar1;
  uint uVar2;
  char cVar3;
  byte bVar4;
  int iVar5;
  undefined8 *puVar6;
  size_t _Size;
  longlong lVar7;
  undefined8 uVar8;
  uint uVar9;
  int iVar10;
  char *pcVar11;
  
  *param_7 = 0;
  if (((param_4 - 1U & 0xfffffffa) != 0) || (uVar9 = 0x20, param_4 == 6)) {
    uVar9 = 0x10;
  }
  uVar9 = param_6 & 0xfffc1ff9 | uVar9;
  if ((param_6 & 0x30) != 0) {
    uVar9 = param_6 & 0xfffc1ff9;
  }
  uVar2 = uVar9 | 0x80;
  if ((uVar9 & 0x180) != 0) {
    uVar2 = uVar9;
  }
  uVar9 = uVar2 | 0x200;
  if ((uVar2 & 0x600) != 0) {
    uVar9 = uVar2;
  }
  uVar2 = uVar9 | 0x800;
  if ((uVar9 & 0x1800) != 0) {
    uVar2 = uVar9;
  }
  uVar9 = uVar2 | 0x80000;
  if ((uVar2 & 0x180000) != 0) {
    uVar9 = uVar2;
  }
  uVar2 = uVar9 | 0x200000;
  if ((uVar9 & 0x600000) != 0) {
    uVar2 = uVar9;
  }
  uVar9 = uVar2 | 0x800000;
  if ((uVar2 & 0x1800000) != 0) {
    uVar9 = uVar2;
  }
  uVar2 = uVar9 | 0x2000000;
  if ((uVar9 & 0x6000000) != 0) {
    uVar2 = uVar9;
  }
  uVar8 = 0x9c8;
  if ((uVar2 & 1) == 0) {
    uVar8 = 0x188;
  }
  puVar6 = (undefined8 *)
           RTMemAllocZTag(uVar8,
                          "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp");
  if (puVar6 == (undefined8 *)0x0) {
    return -8;
  }
  iVar10 = 1;
  *(undefined4 *)((longlong)puVar6 + 0x14) = 1;
  puVar6[0x13] = 0;
  puVar6[1] = 0;
  *(undefined4 *)(puVar6 + 2) = 0;
  puVar6[3] = 0;
  *(undefined4 *)((longlong)puVar6 + 0x2e) = 0;
  *(undefined2 *)((longlong)puVar6 + 0x32) = 0;
  puVar6[7] = 0;
  puVar6[0x10] = 0;
  puVar6[0x11] = param_1;
  if ((uVar2 & 1) != 0) {
    puVar6[0x15] = (longlong)puVar6 + 0x1c7U & 0xffffffffffffffc0;
  }
  *(uint *)(puVar6 + 0x16) = uVar2;
  _Size = nocrt_strlen(param_3);
  *(char *)((longlong)puVar6 + 0xbc) = (char)_Size;
  memcpy((void *)((longlong)puVar6 + 0xbd),param_3,_Size);
  *(int *)(puVar6 + 0x28) = param_4;
  nocrt_strcpy((longlong)puVar6 + 0x144,param_5);
  iVar5 = RTSemEventCreate(puVar6 + 0x10);
  if ((-1 < iVar5) && (iVar5 = RTSpinlockCreate(puVar6 + 1,2,"hAddrSpinlock"), -1 < iVar5)) {
    lVar7 = RTMemAllocTag((ulonglong)*(uint *)((longlong)puVar6 + 0x14) * 0x18,
                          "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp");
    puVar6[3] = lVar7;
    if (lVar7 != 0) {
      pcVar11 = (char *)((longlong)puVar6 + 0x5a);
      do {
        if (iVar5 < 0) goto LAB_180166cf1;
        bVar1 = *(byte *)(puVar6 + 0x16);
        pcVar11[-2] = '\0';
        if (iVar10 == 1) {
          cVar3 = '\x04';
        }
        else if (iVar10 == 2) {
          cVar3 = '\x10';
        }
        else if (iVar10 == 3) {
          cVar3 = '\n';
        }
        else {
          cVar3 = '\0';
        }
        *pcVar11 = cVar3;
        bVar4 = cVar3 + 3U & 0xfc;
        pcVar11[1] = bVar4;
        if ((bVar1 & 1) == 0) {
          pcVar11[-1] = '\0';
          pcVar11[-10] = '\0';
          pcVar11[-9] = '\0';
          pcVar11[-8] = '\0';
          pcVar11[-7] = '\0';
          pcVar11[-6] = '\0';
          pcVar11[-5] = '\0';
          pcVar11[-4] = '\0';
          pcVar11[-3] = '\0';
LAB_180166c52:
          iVar5 = 0;
        }
        else {
          pcVar11[-1] = ' ';
          lVar7 = RTMemAllocZTag((ulonglong)bVar4 << 5,
                                 "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp"
                                );
          *(longlong *)(pcVar11 + -10) = lVar7;
          if (lVar7 != 0) goto LAB_180166c52;
          iVar5 = -8;
        }
        iVar10 = iVar10 + 1;
        pcVar11 = pcVar11 + 0x10;
      } while (iVar10 < 4);
      if (iVar5 < 0) goto LAB_180166cf1;
      lVar7 = SUPR0ObjRegister(param_2,2,FUN_180168540,puVar6,param_1);
      puVar6[0x12] = lVar7;
      if (lVar7 != 0) {
        *puVar6 = *(undefined8 *)(param_1 + 0x10);
        *(undefined8 **)(param_1 + 0x10) = puVar6;
        iVar10 = SUPR0ObjVerifyAccess(puVar6[0x12],param_2,(longlong)puVar6 + 0xbd);
        if ((-1 < iVar10) && (iVar10 = FUN_180167fd0(puVar6,param_2), -1 < iVar10)) {
          *param_7 = puVar6;
          return 0;
        }
        SUPR0ObjRelease(puVar6[0x12],param_2);
        return iVar10;
      }
    }
    iVar5 = -8;
  }
LAB_180166cf1:
  RTSemEventDestroy(puVar6[0x10]);
  puVar6[0x10] = 0;
  RTSpinlockDestroy(puVar6[1]);
  puVar6[1] = 0;
  RTMemFree(puVar6[3]);
  puVar6[3] = 0;
  RTMemFree(puVar6);
  return iVar5;
}

