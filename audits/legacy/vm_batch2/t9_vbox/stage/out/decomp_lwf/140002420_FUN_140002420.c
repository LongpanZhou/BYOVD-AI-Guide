
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int FUN_140002420(undefined8 param_1,undefined8 param_2,ulonglong param_3,undefined8 param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined8 uVar5;
  int *piVar6;
  ulonglong uVar4;
  
  iVar1 = DAT_140034188;
  iVar2 = 0;
  LOCK();
  DAT_140034188 = 3;
  UNLOCK();
  if (iVar1 == 1) {
    param_4 = 0;
    uVar3 = ObReferenceObjectByHandle(DAT_140034190);
    param_3 = (ulonglong)uVar3;
    if (uVar3 == 0) {
      param_4 = 0;
      param_3 = 0;
      param_2 = 0;
      KeWaitForSingleObject(0);
      ObfDereferenceObject(0);
    }
    else {
      param_2 = DAT_140034190;
      DbgPrint("vboxNetLwfWinTryFiniIdc: ObReferenceObjectByHandle(%p) failed with 0x%x\n");
    }
    uVar5 = RTErrConvertFromNtStatus(uVar3);
    iVar2 = (int)uVar5;
  }
  else {
    if (iVar1 != 2) {
      if (iVar1 == 3) {
        DbgPrint("vboxNetLwfWinTryFiniIdc: called in \'Stopping\' state\n");
        return -0x4f;
      }
      goto LAB_1400024ed;
    }
    uVar4 = FUN_140001b80((undefined8 *)&DAT_1400341a0);
    iVar2 = (int)uVar4;
  }
  if (iVar2 < 0) {
    return iVar2;
  }
LAB_1400024ed:
  FUN_140001170((undefined8 *)&DAT_1400341a0);
  _DAT_140034220 = 0;
  _DAT_1400341a0 = 0;
  uRam00000001400341a8 = 0;
  _DAT_1400341b0 = 0;
  uRam00000001400341b8 = 0;
  _DAT_1400341c0 = 0;
  uRam00000001400341c8 = 0;
  _DAT_1400341d0 = 0;
  uRam00000001400341d8 = 0;
  _DAT_1400341e0 = 0;
  uRam00000001400341e8 = 0;
  _DAT_1400341f0 = 0;
  uRam00000001400341f8 = 0;
  _DAT_140034200 = 0;
  uRam0000000140034208 = 0;
  _DAT_140034210 = 0;
  uRam0000000140034218 = 0;
  piVar6 = (int *)RTLogRelSetDefaultInstance(0);
  RTLogDestroy(piVar6);
  piVar6 = (int *)RTLogSetDefaultInstance(0);
  RTLogDestroy(piVar6);
  RTR0Term(piVar6,param_2,param_3,param_4);
  return iVar2;
}

