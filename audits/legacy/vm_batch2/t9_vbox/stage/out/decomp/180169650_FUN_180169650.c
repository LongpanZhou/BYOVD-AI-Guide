
undefined8
FUN_180169650(longlong param_1,uint param_2,undefined8 param_3,longlong param_4,longlong param_5,
             undefined8 param_6)

{
  uint uVar1;
  char cVar2;
  undefined8 uVar3;
  ushort uVar4;
  
  if (param_2 == 0) {
    cVar2 = RTThreadPreemptIsEnabled(0);
    if (cVar2 == '\0') {
      RTSpinlockAcquire(*(undefined8 *)(param_1 + 8));
      if (((*(longlong *)(param_1 + 0x38) != 0) &&
          (uVar1 = *(uint *)(*(longlong *)(param_1 + 0x38) + 0x84), uVar1 != 3)) &&
         (((*(char *)(param_1 + 0x30) != '\0' && ((uVar1 & 2) == 0)) ||
          ((*(char *)(param_1 + 0x33) != '\0' && ((uVar1 & 1) == 0)))))) {
        RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
        return 4;
      }
      RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
    }
    if (((ushort)(*(ushort *)(param_5 + 0xc) >> 8 | *(ushort *)(param_5 + 0xc) << 8) == 0x800) &&
       (*(char *)(param_4 + 0x18) == '\0')) {
      FUN_180168b10(param_1,param_4,param_5);
    }
  }
  else {
    if ((param_2 & 1) != 0) {
      uVar4 = *(ushort *)(param_5 + 0xc);
      if (((ushort)(uVar4 >> 8 | uVar4 << 8) == 0x86dd) && (*(char *)(param_4 + 0x18) == '\0')) {
        FUN_180169e90(param_1,param_4,param_5);
        uVar4 = *(ushort *)(param_5 + 0xc);
      }
      if (((ushort)(uVar4 >> 8 | uVar4 << 8) == 0x806) && (*(char *)(param_4 + 0x18) == '\0')) {
        FUN_180168870(param_1,param_4,param_5);
      }
    }
    if (((((ushort)(*(ushort *)(param_5 + 0xc) >> 8 | *(ushort *)(param_5 + 0xc) << 8) == 0x800) &&
         (0x11a < *(uint *)(param_4 + 0x20))) && (*(char *)(param_4 + 0x18) == '\0')) ||
       ((*(ushort *)(param_4 + 0x26) & 8) != 0)) {
      FUN_18016bc90(param_1,param_4);
    }
  }
  uVar3 = FUN_18016a090(param_1,param_2,param_3,param_6);
  return uVar3;
}

