
undefined8 FUN_18016adc0(longlong param_1,uint param_2,uint param_3,void *param_4)

{
  void *_Dst;
  uint uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  uint uVar4;
  
  uVar4 = (uint)*(ushort *)(param_1 + 0x2c);
  if (uVar4 != 1) {
    if (*(uint *)(param_1 + 0x40) < param_2 + param_3) {
      if (*(uint *)(param_1 + 0x20) < param_2 + param_3) {
        return 0;
      }
      uVar2 = 0;
      uVar3 = uVar2;
      if (*(uint *)(param_1 + 0x40) < param_2) {
        do {
          uVar1 = (int)uVar3 + 1;
          uVar2 = (ulonglong)uVar1;
          param_2 = param_2 - *(int *)(param_1 + 0x40 + uVar3 * 0x18);
          if (uVar4 <= uVar1) {
            return 0;
          }
          uVar3 = uVar2;
        } while (*(uint *)(param_1 + 0x40 + uVar2 * 0x18) < param_2);
      }
      uVar1 = *(int *)(param_1 + 0x40 + uVar2 * 0x18) - param_2;
      _Dst = (void *)((ulonglong)param_2 + *(longlong *)(param_1 + 0x38 + uVar2 * 0x18));
      if (uVar1 < param_3) {
        memcpy(_Dst,param_4,(ulonglong)uVar1);
        param_3 = param_3 - uVar1;
        do {
          param_4 = (void *)((longlong)param_4 + (ulonglong)uVar1);
          uVar1 = (int)uVar2 + 1;
          uVar2 = (ulonglong)uVar1;
          if (uVar4 <= uVar1) {
            return 0;
          }
          uVar1 = param_3;
          if (*(uint *)(param_1 + 0x40 + uVar2 * 0x18) < param_3) {
            uVar1 = *(uint *)(param_1 + 0x40 + uVar2 * 0x18);
          }
          memcpy(*(void **)(param_1 + 0x38 + uVar2 * 0x18),param_4,(ulonglong)uVar1);
          param_3 = param_3 - uVar1;
        } while (param_3 != 0);
      }
      else {
        memcpy(_Dst,param_4,(ulonglong)param_3);
      }
      return 1;
    }
  }
  memcpy((void *)((ulonglong)param_2 + *(longlong *)(param_1 + 0x38)),param_4,(ulonglong)param_3);
  return 1;
}

