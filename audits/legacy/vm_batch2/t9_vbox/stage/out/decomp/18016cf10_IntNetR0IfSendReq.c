
undefined8 IntNetR0IfSendReq(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  
                    /* 0x16cf10  279  IntNetR0IfSendReq */
  if (*(int *)(param_2 + 4) != 0x18) {
    return 0xfffffffe;
  }
  uVar1 = IntNetR0IfSend(*(undefined4 *)(param_2 + 0x10),param_1);
  return uVar1;
}

