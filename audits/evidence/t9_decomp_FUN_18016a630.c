
int FUN_18016a630(longlong param_1,int param_2,longlong param_3,short *param_4,uint *param_5)

{
  int *piVar1;
  uint uVar2;
  longlong lVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  ulonglong uVar7;
  longlong lVar8;
  int iVar9;
  int iVar10;
  
  RTSpinlockAcquire(*(undefined8 *)(param_1 + 8));
  iVar9 = 0;
  *param_5 = 0;
  iVar10 = 1;
  param_5[2] = 0;
  param_5[3] = 0;
  param_5[4] = 0;
  uVar7 = (ulonglong)*(uint *)(param_1 + 0x10);
  if (*(uint *)(param_1 + 0x10) == 0) {
LAB_18016a7d7:
    if (param_2 != 2) goto LAB_18016a7dd;
  }
  else {
    lVar8 = uVar7 * 0x18;
    do {
      lVar8 = lVar8 + -0x18;
      psVar5 = (short *)(*(longlong *)(param_1 + 0x18) + lVar8);
      uVar6 = (int)uVar7 - 1;
      uVar7 = (ulonglong)uVar6;
      if (((char)psVar5[4] != '\0') &&
         (((((psVar5[2] == param_4[2] && (psVar5[1] == param_4[1])) &&
            (iVar4 = iVar10, *psVar5 == *param_4)) ||
           ((iVar4 = 0, *psVar5 == -1 || (*(char *)((longlong)psVar5 + 7) != '\0')))) ||
          ((param_2 == 0 && ((char)psVar5[3] != '\0')))))) {
        lVar3 = *(longlong *)(psVar5 + 8);
        iVar9 = iVar9 + iVar4;
        if (lVar3 != param_3) {
          uVar2 = param_5[4];
          param_5[4] = uVar2 + 1;
          *(longlong *)(param_5 + (ulonglong)uVar2 * 4 + 6) = lVar3;
          *(undefined1 *)(param_5 + ((ulonglong)uVar2 + 2) * 4) = 0;
          LOCK();
          *(int *)(lVar3 + 0xb0) = *(int *)(lVar3 + 0xb0) + 1;
          UNLOCK();
        }
      }
    } while (uVar6 != 0);
    if (iVar9 == 0) goto LAB_18016a7d7;
    if (param_2 != 0) {
      if ((*(int *)(param_1 + 0x24) != 0) &&
         (uVar7 = (ulonglong)*(uint *)(param_1 + 0x10), *(uint *)(param_1 + 0x10) != 0)) {
        lVar8 = uVar7 * 0x18;
        do {
          lVar8 = lVar8 + -0x18;
          psVar5 = (short *)(*(longlong *)(param_1 + 0x18) + lVar8);
          uVar6 = (int)uVar7 - 1;
          uVar7 = (ulonglong)uVar6;
          if ((((((char)psVar5[3] != '\0') && (*(char *)((longlong)psVar5 + 7) == '\0')) &&
               ((char)psVar5[4] != '\0')) &&
              (((psVar5[2] != param_4[2] || (psVar5[1] != param_4[1])) || (*psVar5 != *param_4))))
             && (*psVar5 != -1)) {
            uVar2 = param_5[4];
            lVar3 = *(longlong *)(psVar5 + 8);
            param_5[4] = uVar2 + 1;
            *(longlong *)(param_5 + (ulonglong)uVar2 * 4 + 6) = lVar3;
            *(undefined1 *)(param_5 + ((ulonglong)uVar2 + 2) * 4) = 0;
            LOCK();
            piVar1 = (int *)(lVar3 + 0xb0);
            *piVar1 = *piVar1 + 1;
            UNLOCK();
          }
        } while (uVar6 != 0);
      }
      goto LAB_18016a7d7;
    }
LAB_18016a7dd:
    if ((*(char *)(param_1 + 0x30) != '\0') &&
       ((((*(short *)(param_1 + 0x2c) == param_4[2] && (*(short *)(param_1 + 0x2a) == param_4[1]))
         && (*(short *)(param_1 + 0x28) == *param_4)) ||
        ((iVar10 = 0, *(short *)(param_1 + 0x28) == -1 || (*(char *)(param_1 + 0x2e) != '\0')))))) {
      iVar9 = iVar9 + iVar10;
      *param_5 = *param_5 | 2;
    }
    if (param_2 == 1) goto LAB_18016a830;
  }
  if ((*(char *)(param_1 + 0x33) != '\0') && ((iVar9 == 0 || (*(char *)(param_1 + 0x31) != '\0'))))
  {
    *param_5 = *param_5 | 1;
  }
LAB_18016a830:
  if (*param_5 != 0) {
    lVar8 = *(longlong *)(param_1 + 0x38);
    *(longlong *)(param_5 + 2) = lVar8;
    if (lVar8 != 0) {
      LOCK();
      *(int *)(lVar8 + 0x80) = *(int *)(lVar8 + 0x80) + 1;
      UNLOCK();
    }
  }
  RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
  if (param_5[4] == 0) {
    iVar9 = 3;
    if (*param_5 == 0) {
      iVar9 = 5;
    }
  }
  else {
    iVar9 = 2 - (uint)(*param_5 != 0);
  }
  return iVar9;
}

