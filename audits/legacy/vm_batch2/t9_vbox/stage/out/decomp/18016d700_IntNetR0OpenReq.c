
undefined8 IntNetR0OpenReq(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
                    /* 0x16d700  289  IntNetR0OpenReq */
  if (*(int *)(param_2 + 4) != 0xe8) {
    return 0xfffffffe;
  }
  uVar1 = IntNetR0Open(param_1,param_2 + 0x10,*(undefined4 *)(param_2 + 0xd0),param_2 + 0x90,
                       *(undefined4 *)(param_2 + 0xd4),*(undefined4 *)(param_2 + 0xd8),
                       *(undefined4 *)(param_2 + 0xdc),0,0,param_2 + 0xe0);
  return uVar1;
}

