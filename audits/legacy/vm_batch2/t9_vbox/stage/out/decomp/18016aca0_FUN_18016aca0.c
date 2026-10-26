
undefined8 FUN_18016aca0(longlong param_1,uint param_2,uint param_3,void *param_4)

{
  longlong lVar1;
  ushort uVar2;
  void *_Src;
  uint uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  
  if (param_2 + param_3 <= *(uint *)(param_1 + 0x40)) {
    memcpy(param_4,(void *)((ulonglong)param_2 + *(longlong *)(param_1 + 0x38)),(ulonglong)param_3);
    return 1;
  }
  if (*(uint *)(param_1 + 0x20) < param_2 + param_3) {
    return 0;
  }
  uVar4 = 0;
  uVar2 = *(ushort *)(param_1 + 0x2c);
  uVar5 = uVar4;
  if (*(uint *)(param_1 + 0x40) < param_2) {
    do {
      uVar3 = (int)uVar5 + 1;
      uVar4 = (ulonglong)uVar3;
      param_2 = param_2 - *(int *)(param_1 + 0x40 + uVar5 * 0x18);
      if (uVar2 <= uVar3) {
        return 0;
      }
      uVar5 = uVar4;
    } while (*(uint *)(param_1 + 0x40 + uVar4 * 0x18) < param_2);
  }
  uVar3 = *(int *)(param_1 + 0x40 + uVar4 * 0x18) - param_2;
  _Src = (void *)((ulonglong)param_2 + *(longlong *)(param_1 + 0x38 + uVar4 * 0x18));
  if (uVar3 < param_3) {
    memcpy(param_4,_Src,(ulonglong)uVar3);
    param_3 = param_3 - uVar3;
    do {
      param_4 = (void *)((longlong)param_4 + (ulonglong)uVar3);
      uVar3 = (int)uVar4 + 1;
      uVar4 = (ulonglong)uVar3;
      if (uVar2 <= uVar3) {
        return 0;
      }
      lVar1 = param_1 + uVar4 * 0x18;
      uVar3 = param_3;
      if (*(uint *)(param_1 + 0x40 + uVar4 * 0x18) < param_3) {
        uVar3 = *(uint *)(lVar1 + 0x40);
      }
      memcpy(param_4,*(void **)(lVar1 + 0x38),(ulonglong)uVar3);
      param_3 = param_3 - uVar3;
    } while (param_3 != 0);
  }
  else {
    memcpy(param_4,_Src,(ulonglong)param_3);
  }
  return 1;
}

