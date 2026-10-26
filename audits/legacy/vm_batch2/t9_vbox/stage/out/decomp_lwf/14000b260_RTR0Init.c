
ulonglong RTR0Init(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  
                    /* 0xb260  155  RTR0Init */
  iVar1 = DAT_140034250;
  LOCK();
  DAT_140034250 = DAT_140034250 + 1;
  UNLOCK();
  uVar2 = iVar1 + 1;
  if (uVar2 != 1) {
    if (uVar2 < 2) {
      LOCK();
      DAT_140034250 = iVar1;
      UNLOCK();
      return 0xffffff1d;
    }
    return 0;
  }
  uVar3 = FUN_140011510();
  if (-1 < (int)uVar3) {
    uVar3 = FUN_140013330();
    if (-1 < (int)uVar3) {
      uVar3 = FUN_140012160();
      if (-1 < (int)uVar3) {
        uVar3 = FUN_140012640();
        if (-1 < (int)uVar3) {
          return uVar3;
        }
        FUN_1400121b0();
      }
      FUN_140013600(param_1,param_2,param_3,param_4);
    }
    thunk_FUN_14001c680();
  }
  return uVar3 & 0xffffffff;
}

