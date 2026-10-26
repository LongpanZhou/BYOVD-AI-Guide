
void FUN_180168320(longlong param_1,int *param_2,undefined8 param_3,longlong param_4)

{
  int *piVar1;
  longlong lVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  longlong lVar6;
  int *piVar7;
  uint uVar8;
  
  uVar8 = param_2[4];
  if (uVar8 != 0) {
    piVar7 = param_2 + (ulonglong)uVar8 * 4 + 6;
    do {
      lVar2 = *(longlong *)(piVar7 + -4);
      piVar1 = piVar7 + -4;
      uVar8 = uVar8 - 1;
      lVar6 = lVar2;
      if ((char)piVar7[-2] == '\0') {
        lVar6 = 0;
      }
      RTSpinlockAcquire(*(undefined8 *)(lVar2 + 0xa8));
      iVar4 = FUN_18016aac0(*(longlong *)(lVar2 + 0x18) + 0x10,param_3,lVar6);
      RTSpinlockRelease(*(undefined8 *)(lVar2 + 0xa8));
      if (iVar4 < 0) {
        if ((((*(char *)(lVar2 + 8) != '\0') && (*(uint *)(lVar2 + 0x10) < 4)) && (param_4 != 0)) &&
           (cVar3 = RTThreadPreemptIsEnabled(0), cVar3 != '\0')) {
          iVar4 = 1;
          do {
            RTSemEventSignal(*(undefined8 *)(lVar2 + 0x38));
            RTThreadYield();
            RTSpinlockAcquire(*(undefined8 *)(lVar2 + 0xa8));
            iVar5 = FUN_18016aac0(*(longlong *)(lVar2 + 0x18) + 0x10,param_3,lVar6);
            RTSpinlockRelease(*(undefined8 *)(lVar2 + 0xa8));
            if (-1 < iVar5) {
              *(longlong *)(*(longlong *)(lVar2 + 0x18) + 0x70) =
                   *(longlong *)(*(longlong *)(lVar2 + 0x18) + 0x70) + 1;
              goto LAB_18016845c;
            }
            *(int *)(lVar2 + 0x10) = *(int *)(lVar2 + 0x10) + 1;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
          *(longlong *)(*(longlong *)(lVar2 + 0x18) + 0x78) =
               *(longlong *)(*(longlong *)(lVar2 + 0x18) + 0x78) + 1;
        }
        *(longlong *)(*(longlong *)(lVar2 + 0x18) + 0x80) =
             *(longlong *)(*(longlong *)(lVar2 + 0x18) + 0x80) + 1;
      }
      else {
        *(undefined4 *)(lVar2 + 0x10) = 0;
      }
LAB_18016845c:
      RTSemEventSignal(*(undefined8 *)(lVar2 + 0x38));
      LOCK();
      piVar7 = (int *)(lVar2 + 0xb0);
      iVar4 = *piVar7;
      *piVar7 = *piVar7 + -1;
      UNLOCK();
      if ((iVar4 == 0x40000001) && (*(longlong *)(lVar2 + 0x50) != 0)) {
        RTSemEventSignal();
      }
      piVar1[0] = 0;
      piVar1[1] = 0;
      piVar7 = piVar1;
    } while (uVar8 != 0);
  }
  param_2[4] = 0;
  if (*param_2 != 0) {
    lVar2 = *(longlong *)(param_2 + 2);
    if (lVar2 != 0) {
      if (param_4 != 0) {
        FUN_18016b930(lVar2,param_1,param_4,*param_2,param_3);
      }
      LOCK();
      piVar7 = (int *)(lVar2 + 0x80);
      iVar4 = *piVar7;
      *piVar7 = *piVar7 + -1;
      UNLOCK();
      if ((iVar4 == 0x40000001) && (param_1 != 0)) {
        RTSemEventSignal();
      }
    }
    param_2[2] = 0;
    param_2[3] = 0;
    *param_2 = 0;
  }
  return;
}

