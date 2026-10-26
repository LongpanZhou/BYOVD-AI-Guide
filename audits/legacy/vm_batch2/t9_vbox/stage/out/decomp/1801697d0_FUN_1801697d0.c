
/* WARNING: Removing unreachable block (ram,0x000180169953) */
/* WARNING: Removing unreachable block (ram,0x000180169959) */

ulonglong FUN_1801697d0(longlong param_1,longlong param_2,longlong param_3,uint *param_4)

{
  int *piVar1;
  uint uVar2;
  longlong lVar3;
  char cVar4;
  ushort uVar5;
  ulonglong uVar6;
  ushort uVar7;
  uint uVar8;
  longlong lVar9;
  undefined1 local_18 [16];
  
  uVar7 = *(ushort *)(param_3 + 0xc);
  uVar5 = uVar7 >> 8 | uVar7 << 8;
  if (uVar5 == 0x800) {
    cVar4 = FUN_18016aca0(param_2,0x1e,4,local_18);
    if (cVar4 != '\0') {
      uVar6 = FUN_18016a180(param_1,param_3,1,local_18,4,1,param_4);
      if (*(uint *)(param_2 + 0x20) < 0x11b) {
        return uVar6;
      }
      if (*(char *)(param_2 + 0x18) != '\0') {
        return uVar6;
      }
      FUN_18016bc90(param_1,param_2,
                    *(ushort *)(param_3 + 0xc) >> 8 | *(ushort *)(param_3 + 0xc) << 8);
      return uVar6 & 0xffffffff;
    }
  }
  else {
    if (uVar5 == 0x806) {
      if (((ushort)(uVar7 >> 8 | uVar7 << 8) == 0x806) && (*(char *)(param_2 + 0x18) == '\0')) {
        FUN_180168870(param_1,param_2,param_3);
        uVar7 = *(ushort *)(param_3 + 0xc);
      }
      if (((((ushort)(uVar7 >> 8 | uVar7 << 8) == 0x800) && (0x11a < *(uint *)(param_2 + 0x20))) &&
          (*(char *)(param_2 + 0x18) == '\0')) || ((*(ushort *)(param_2 + 0x26) & 8) != 0)) {
        FUN_18016bc90(param_1,param_2);
      }
      uVar6 = FUN_18016a090(param_1,1,0,param_4);
      return uVar6;
    }
    if (uVar5 != 0x86dd) {
      RTSpinlockAcquire(*(undefined8 *)(param_1 + 8));
      uVar8 = 0;
      *param_4 = 0;
      param_4[2] = 0;
      param_4[3] = 0;
      param_4[4] = 0;
      uVar6 = (ulonglong)*(uint *)(param_1 + 0x10);
      if (*(uint *)(param_1 + 0x10) != 0) {
        lVar9 = uVar6 * 0x18;
        do {
          lVar3 = *(longlong *)(param_1 + 0x18);
          uVar8 = (int)uVar6 - 1;
          uVar6 = (ulonglong)uVar8;
          if ((*(char *)(lVar9 + -0x10 + lVar3) != '\0') &&
             (*(char *)(lVar9 + -0x11 + lVar3) != '\0')) {
            lVar3 = *(longlong *)(lVar9 + -8 + lVar3);
            uVar2 = param_4[4];
            param_4[4] = uVar2 + 1;
            *(longlong *)(param_4 + (ulonglong)uVar2 * 4 + 6) = lVar3;
            *(undefined1 *)(param_4 + ((ulonglong)uVar2 + 2) * 4) = 0;
            LOCK();
            piVar1 = (int *)(lVar3 + 0xb0);
            *piVar1 = *piVar1 + 1;
            UNLOCK();
          }
          lVar9 = lVar9 + -0x18;
        } while (uVar8 != 0);
        uVar8 = *param_4;
      }
      if (*(char *)(param_1 + 0x30) != '\0') {
        uVar8 = uVar8 | 2;
        *param_4 = uVar8;
      }
      *param_4 = uVar8 & 0xfffffffe;
      if ((uVar8 & 0xfffffffe) != 0) {
        lVar9 = *(longlong *)(param_1 + 0x38);
        *(longlong *)(param_4 + 2) = lVar9;
        if (lVar9 != 0) {
          LOCK();
          *(int *)(lVar9 + 0x80) = *(int *)(lVar9 + 0x80) + 1;
          UNLOCK();
        }
      }
      RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
      if (param_4[4] == 0) {
        if (*param_4 != 0) {
          return 3;
        }
        return 5;
      }
      return (ulonglong)(2 - (*param_4 != 0));
    }
    cVar4 = FUN_18016aca0(param_2,0x26,0x10,local_18);
    if (cVar4 != '\0') {
      uVar6 = FUN_18016a180(param_1,param_3,2,local_18,0x10,1,param_4);
      return uVar6;
    }
  }
  uVar6 = FUN_18016a5a0(param_1,1,param_4);
  return uVar6;
}

