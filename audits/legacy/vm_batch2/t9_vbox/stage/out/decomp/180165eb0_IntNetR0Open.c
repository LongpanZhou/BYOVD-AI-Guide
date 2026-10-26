
ulonglong IntNetR0Open(undefined8 param_1,ulonglong param_2,int param_3,char *param_4,uint param_5,
                      undefined4 param_6,undefined4 param_7,undefined8 param_8,undefined8 param_9,
                      ulonglong param_10)

{
  int *piVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined8 uVar4;
  uint uVar5;
  uint *puVar6;
  undefined8 in_stack_ffffffffffffffb0;
  undefined4 uVar7;
  longlong local_38 [2];
  
  piVar1 = DAT_1801dd690;
                    /* 0x165eb0  8  IntNetR0Open */
  uVar7 = (undefined4)((ulonglong)in_stack_ffffffffffffffb0 >> 0x20);
  if (DAT_1801dd690 + 0x400 < (int *)0x2000) {
    return 0xfffffffe;
  }
  if ((((ulonglong)DAT_1801dd690 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) != 0)
  {
    return 0xfffffffe;
  }
  if (*DAT_1801dd690 == 0) {
    return 0xfffffffd;
  }
  if (param_2 + 0x1000 < 0x2000) {
    return 0xfffffffe;
  }
  if (((param_2 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) != 0) {
    return 0xfffffffe;
  }
  uVar2 = RTStrEnd(param_2);
  if (uVar2 == 0) {
    return 0xfffffffe;
  }
  if (uVar2 == param_2) {
    return 0xfffffffe;
  }
  if (param_4 == (char *)0x0) {
    param_4 = "";
  }
  else {
    if (param_4 + 0x1000 < (char *)0x2000) {
      return 0xfffffffe;
    }
    if ((((ulonglong)param_4 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) != 0) {
      return 0xfffffffe;
    }
    lVar3 = RTStrEnd(param_4);
    if (lVar3 == 0) {
      return 0xfffffffe;
    }
  }
  if (4 < param_3 - 1U) {
    return 0xfffffffe;
  }
  if ((param_3 == 1) || (param_3 == 2)) {
LAB_180165fef:
    if (*param_4 != '\0') {
      return 0xfffffffe;
    }
  }
  else {
    if ((param_3 != 3) && (param_3 != 4)) {
      if (param_3 != 5) {
        return 0xfffffff4;
      }
      goto LAB_180165fef;
    }
    if (*param_4 == '\0') {
      return 0xfffffffe;
    }
  }
  if ((param_5 & 0x7c000000) != 0) {
    return 0xfffffffe;
  }
  uVar5 = 0;
  puVar6 = &DAT_1801a78dc;
  do {
    if ((*puVar6 & param_5) == *puVar6) {
      return 0xfffffffe;
    }
    uVar5 = uVar5 + 1;
    puVar6 = puVar6 + 4;
  } while (uVar5 < 8);
  uVar5 = 0;
  puVar6 = &DAT_1801a795c;
  do {
    if ((*puVar6 & param_5) == *puVar6) {
      return 0xfffffffe;
    }
    uVar5 = uVar5 + 1;
    puVar6 = puVar6 + 4;
  } while (uVar5 < 2);
  if (param_10 + 0x1000 < 0x2000) {
    return 0xfffffffe;
  }
  if (((param_10 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) != 0) {
    return 0xfffffffe;
  }
  uVar2 = RTSemMutexRequest(*(undefined8 *)(piVar1 + 2),0xffffffff);
  if ((int)uVar2 < 0) {
    return uVar2;
  }
  local_38[0] = 0;
  uVar5 = FUN_18016a8a0(piVar1,param_1,param_2,param_3,param_4,CONCAT44(uVar7,param_5),local_38);
  lVar3 = local_38[0];
  uVar2 = (ulonglong)uVar5;
  if ((int)uVar5 < 0) {
    if (uVar5 != 0xffffffb2) goto LAB_1801661d5;
    uVar5 = FUN_1801669d0(piVar1,param_1,param_2,param_3,param_4,param_5,local_38);
    lVar3 = local_38[0];
    uVar2 = (ulonglong)uVar5;
    if ((int)uVar5 < 0) goto LAB_1801661d5;
    uVar5 = FUN_180167b10(local_38[0],param_1,param_6,param_7,param_5,param_8,param_9,param_10);
    uVar2 = (ulonglong)uVar5;
    if (-1 < (int)uVar5) goto LAB_1801661d5;
    uVar4 = *(undefined8 *)(lVar3 + 0x90);
  }
  else {
    uVar5 = FUN_180167b10(local_38[0],param_1,param_6,param_7,param_5,param_8,param_9,param_10);
    uVar2 = (ulonglong)uVar5;
    if (-1 < (int)uVar5) {
      FUN_180166660(lVar3,param_5);
      RTSemMutexRelease(*(undefined8 *)(piVar1 + 2));
      return 0x1c;
    }
    uVar4 = *(undefined8 *)(lVar3 + 0x90);
  }
  SUPR0ObjRelease(uVar4,param_1);
LAB_1801661d5:
  RTSemMutexRelease(*(undefined8 *)(piVar1 + 2));
  return uVar2;
}

