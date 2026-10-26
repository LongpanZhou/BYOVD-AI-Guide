
undefined8 FUN_18016a090(longlong param_1,uint param_2,longlong param_3,uint *param_4)

{
  uint uVar1;
  longlong lVar2;
  uint uVar3;
  ulonglong uVar4;
  longlong lVar5;
  
  RTSpinlockAcquire(*(undefined8 *)(param_1 + 8));
  uVar3 = 0;
  *param_4 = 0;
  param_4[2] = 0;
  param_4[3] = 0;
  param_4[4] = 0;
  uVar4 = (ulonglong)*(uint *)(param_1 + 0x10);
  if (*(uint *)(param_1 + 0x10) != 0) {
    lVar5 = uVar4 * 0x18;
    do {
      uVar3 = (int)uVar4 - 1;
      uVar4 = (ulonglong)uVar3;
      if ((*(char *)(lVar5 + -0x10 + *(longlong *)(param_1 + 0x18)) != '\0') &&
         (lVar2 = *(longlong *)(lVar5 + -8 + *(longlong *)(param_1 + 0x18)), lVar2 != param_3)) {
        uVar1 = param_4[4];
        param_4[4] = uVar1 + 1;
        *(longlong *)(param_4 + (ulonglong)uVar1 * 4 + 6) = lVar2;
        *(undefined1 *)(param_4 + ((ulonglong)uVar1 + 2) * 4) = 0;
        LOCK();
        *(int *)(lVar2 + 0xb0) = *(int *)(lVar2 + 0xb0) + 1;
        UNLOCK();
      }
      lVar5 = lVar5 + -0x18;
    } while (uVar3 != 0);
    uVar3 = *param_4;
  }
  if (*(char *)(param_1 + 0x30) != '\0') {
    uVar3 = uVar3 | 2;
    *param_4 = uVar3;
  }
  if (*(char *)(param_1 + 0x33) != '\0') {
    uVar3 = uVar3 | 1;
  }
  *param_4 = ~param_2 & uVar3;
  if ((~param_2 & uVar3) != 0) {
    lVar5 = *(longlong *)(param_1 + 0x38);
    *(longlong *)(param_4 + 2) = lVar5;
    if (lVar5 != 0) {
      LOCK();
      *(int *)(lVar5 + 0x80) = *(int *)(lVar5 + 0x80) + 1;
      UNLOCK();
    }
  }
  RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
  return 1;
}

