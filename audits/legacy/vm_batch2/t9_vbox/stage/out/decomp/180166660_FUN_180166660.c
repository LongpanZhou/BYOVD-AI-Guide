
undefined8 FUN_180166660(longlong param_1,uint param_2)

{
  uint uVar1;
  longlong lVar2;
  longlong lVar3;
  bool bVar4;
  bool bVar5;
  undefined1 uVar6;
  longlong lVar7;
  uint *puVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  ulonglong uVar12;
  
  uVar11 = *(uint *)(param_1 + 0xb4);
  uVar9 = uVar11;
  if (((param_2 & 4) != 0) && (uVar9 = uVar11 | param_2 & 0x3329520, uVar9 != uVar11)) {
    lVar7 = RTLogRelGetDefaultInstanceEx(0x17b0010);
    if (lVar7 != 0) {
      RTLogLoggerEx(lVar7,0x10,0x17b,"INTNET: %s - min flags changed %#x -> %#x\n",param_1 + 0xbd,
                    *(undefined4 *)(param_1 + 0xb4),uVar9);
    }
    *(uint *)(param_1 + 0xb4) = uVar9;
  }
  uVar11 = *(uint *)(param_1 + 0xb0);
  puVar8 = &DAT_1801a78d8;
  lVar7 = 8;
  uVar10 = uVar11;
  do {
    uVar1 = puVar8[1];
    if (((param_2 & uVar1) != 0) && ((*puVar8 & uVar10) == 0)) {
      if ((puVar8[-2] & (uVar9 | param_2)) == 0) {
        if ((param_2 & 4) == 0) {
          uVar10 = uVar10 & ~uVar1 | puVar8[-1];
        }
      }
      else {
        uVar10 = uVar10 & ~uVar1 | puVar8[-2];
      }
    }
    puVar8 = puVar8 + 4;
    lVar7 = lVar7 + -1;
  } while (lVar7 != 0);
  uVar9 = uVar10 | param_2 & 0x40048;
  if (uVar11 == uVar9) {
    return 0;
  }
  lVar7 = RTLogRelGetDefaultInstanceEx(0x17b0010);
  if (lVar7 != 0) {
    RTLogLoggerEx(lVar7,0x10,0x17b,"INTNET: %s - flags changed %#x -> %#x\n",param_1 + 0xbd,uVar11,
                  uVar9);
  }
  RTSpinlockAcquire();
  *(uint *)(param_1 + 0xb0) = uVar9;
  if ((*(longlong *)(param_1 + 0x38) == 0) || (*(int *)(param_1 + 0xb8) == 0)) {
    bVar5 = false;
  }
  else {
    bVar4 = true;
    bVar5 = true;
    if ((uVar10 & 0x80000) != 0) {
      uVar6 = 1;
      goto LAB_1801667b6;
    }
  }
  bVar4 = bVar5;
  uVar6 = 0;
LAB_1801667b6:
  *(undefined1 *)(param_1 + 0x30) = uVar6;
  if (((*(char *)(param_1 + 0x2f) == '\0') && ((uVar10 & 0x400000) == 0)) || ((uVar10 & 0x200) == 0)
     ) {
    uVar6 = 0;
  }
  else {
    uVar6 = 1;
  }
  *(undefined1 *)(param_1 + 0x2e) = uVar6;
  if ((bVar4) && ((uVar10 & 0x80000) != 0)) {
    uVar6 = 1;
  }
  else {
    uVar6 = 0;
  }
  *(undefined1 *)(param_1 + 0x33) = uVar6;
  *(byte *)(param_1 + 0x32) = (byte)(uVar10 >> 0x1a) & 1;
  if (((uVar10 & 0x4000000) == 0) || ((uVar10 & 0x800) == 0)) {
    uVar6 = 0;
  }
  else {
    uVar6 = 1;
  }
  *(undefined1 *)(param_1 + 0x31) = uVar6;
  if ((char)((byte)uVar11 ^ (byte)uVar9) < '\0') {
    uVar12 = (ulonglong)*(uint *)(param_1 + 0x10);
    *(undefined8 *)(param_1 + 0x20) = 0;
    if (*(uint *)(param_1 + 0x10) != 0) {
      lVar7 = uVar12 * 0x18;
      do {
        lVar2 = *(longlong *)(param_1 + 0x18);
        uVar11 = (int)uVar12 - 1;
        uVar12 = (ulonglong)uVar11;
        lVar3 = *(longlong *)(lVar7 + -8 + lVar2);
        if ((lVar3 != 0) && (*(char *)(lVar3 + 7) != '\0')) {
          if (((char)(byte)uVar9 < '\0') && ((*(uint *)(lVar3 + 0xc) & 0x4000) != 0)) {
            *(undefined1 *)(lVar7 + -0x12 + lVar2) = 1;
            bVar5 = true;
            if ((*(uint *)(lVar3 + 0xc) & 0x10000) == 0) goto LAB_180166879;
            *(undefined1 *)(lVar7 + -0x11 + lVar2) = 1;
          }
          else {
            *(undefined1 *)(lVar7 + -0x12 + lVar2) = 0;
            bVar5 = false;
LAB_180166879:
            *(undefined1 *)(lVar7 + -0x11 + lVar2) = 0;
            if (!bVar5) goto LAB_180166891;
          }
          *(int *)(param_1 + 0x20) = *(int *)(param_1 + 0x20) + 1;
          if (*(char *)(lVar7 + -0x11 + lVar2) == '\0') {
            *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + 1;
          }
        }
LAB_180166891:
        lVar7 = lVar7 + -0x18;
      } while (uVar11 != 0);
    }
  }
  RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
  return 0;
}

