
undefined4 IntNetR0IfWait(undefined4 param_1,undefined8 param_2,undefined4 param_3)

{
  longlong lVar1;
  undefined4 uVar2;
  int iVar3;
  longlong lVar4;
  
                    /* 0x16d4d0  286  IntNetR0IfWait */
  if ((DAT_1801dd690 + 0x400 < (int *)0x2000) ||
     ((((ulonglong)DAT_1801dd690 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) != 0))
  {
    return 0xfffffffe;
  }
  if (*DAT_1801dd690 == 0) {
    return 0xfffffffd;
  }
  lVar4 = RTHandleTableLookupWithCtx(*(undefined8 *)(DAT_1801dd690 + 6),param_1,param_2);
  if (lVar4 == 0) {
    return 0xfffffffc;
  }
  lVar1 = *(longlong *)(lVar4 + 0x38);
  if (*(longlong *)(lVar4 + 0x48) == -1) {
    if ((*(char *)(lVar4 + 9) == '\0') && (lVar1 != 0)) {
      LOCK();
      *(int *)(lVar4 + 0x40) = *(int *)(lVar4 + 0x40) + 1;
      UNLOCK();
      uVar2 = RTSemEventWaitNoResume(lVar1,param_3);
      if (*(longlong *)(lVar4 + 0x38) == lVar1) {
        LOCK();
        *(int *)(lVar4 + 0x40) = *(int *)(lVar4 + 0x40) + -1;
        UNLOCK();
        if ((*(longlong *)(lVar4 + 0x48) == -1) &&
           (iVar3 = SUPR0ObjRelease(*(undefined8 *)(lVar4 + 0x60),param_2), iVar3 != 0x55)) {
          return uVar2;
        }
      }
    }
    else {
      SUPR0ObjRelease(*(undefined8 *)(lVar4 + 0x60),param_2);
    }
  }
  return 0xfffffe95;
}

