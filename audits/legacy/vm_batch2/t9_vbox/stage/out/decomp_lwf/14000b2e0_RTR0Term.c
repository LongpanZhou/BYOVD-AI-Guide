
void RTR0Term(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  
                    /* 0xb2e0  157  RTR0Term */
  LOCK();
  UNLOCK();
  if (DAT_140034250 == 1) {
    DAT_140034250 = DAT_140034250 + -1;
    FUN_140013600(param_1,param_2,param_3,param_4);
    FUN_140012660();
    FUN_1400121b0();
    thunk_FUN_14001c680();
    return;
  }
  iVar1 = DAT_140034250 + -1;
  if (DAT_140034250 + -1 < 0) {
    LOCK();
    UNLOCK();
    iVar1 = DAT_140034250;
  }
  DAT_140034250 = iVar1;
  return;
}

