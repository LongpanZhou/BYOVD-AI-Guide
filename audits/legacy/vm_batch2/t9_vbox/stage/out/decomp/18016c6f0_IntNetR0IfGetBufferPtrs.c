
int IntNetR0IfGetBufferPtrs
              (undefined4 param_1,undefined8 param_2,undefined8 *param_3,undefined8 *param_4)

{
  int *piVar1;
  int iVar2;
  longlong lVar3;
  
                    /* 0x16c6f0  276  IntNetR0IfGetBufferPtrs */
  piVar1 = DAT_1801dd690;
  if (((int *)0x1fff < DAT_1801dd690 + 0x400) &&
     ((((ulonglong)DAT_1801dd690 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) == 0))
  {
    if (*DAT_1801dd690 == 0) {
      return -3;
    }
    if (((((undefined8 *)0x1fff < param_3 + 0x200) &&
         ((((ulonglong)param_3 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) == 0))
        || (param_3 == (undefined8 *)0x0)) &&
       ((((undefined8 *)0x1fff < param_4 + 0x200 &&
         ((((ulonglong)param_4 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) == 0))
        || (param_4 == (undefined8 *)0x0)))) {
      if (param_3 != (undefined8 *)0x0) {
        *param_3 = 0;
      }
      if (param_4 != (undefined8 *)0x0) {
        *param_4 = 0;
      }
      lVar3 = RTHandleTableLookupWithCtx(*(undefined8 *)(piVar1 + 6),param_1,param_2);
      if (lVar3 == 0) {
        iVar2 = -4;
      }
      else {
        iVar2 = RTSemMutexRequest(*(undefined8 *)(piVar1 + 2),0xffffffff);
        if (-1 < iVar2) {
          if (param_3 != (undefined8 *)0x0) {
            *param_3 = *(undefined8 *)(lVar3 + 0x20);
          }
          if (param_4 != (undefined8 *)0x0) {
            *param_4 = *(undefined8 *)(lVar3 + 0x18);
          }
          iVar2 = RTSemMutexRelease(*(undefined8 *)(piVar1 + 2));
        }
        SUPR0ObjRelease(*(undefined8 *)(lVar3 + 0x60),param_2);
      }
      return iVar2;
    }
  }
  return -2;
}

