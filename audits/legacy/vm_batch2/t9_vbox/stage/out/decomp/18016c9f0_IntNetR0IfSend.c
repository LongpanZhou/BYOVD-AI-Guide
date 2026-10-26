
undefined4 IntNetR0IfSend(undefined4 param_1,undefined8 param_2)

{
  int *piVar1;
  int iVar2;
  longlong lVar3;
  char cVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  ushort uVar9;
  longlong lVar10;
  longlong lVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  undefined4 uVar14;
  undefined4 extraout_var;
  uint *puVar15;
  byte *pbVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  undefined8 uVar20;
  undefined4 uVar21;
  longlong lVar22;
  bool bVar23;
  undefined8 local_88;
  undefined8 uStack_80;
  undefined8 local_78;
  undefined4 local_70;
  byte local_6c;
  undefined2 local_6b;
  undefined1 local_69;
  uint local_68;
  undefined2 local_64;
  undefined2 local_62;
  undefined4 local_60;
  undefined2 local_5c;
  undefined8 local_58;
  byte *local_50;
  uint local_48;
  
                    /* 0x16c9f0  278  IntNetR0IfSend */
  if ((DAT_1801dd690 + 0x400 < (int *)0x2000) ||
     ((((ulonglong)DAT_1801dd690 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) != 0))
  {
    return 0xfffffffe;
  }
  if (*DAT_1801dd690 == 0) {
    return 0xfffffffd;
  }
  lVar11 = RTHandleTableLookupWithCtx(*(undefined8 *)(DAT_1801dd690 + 6),param_1,param_2);
  if (lVar11 == 0) {
    return 0xfffffffc;
  }
  uVar13 = rdtsc();
  uVar12 = CONCAT44((int)((ulonglong)lVar11 >> 0x20),(int)uVar13) | uVar13 & 0xffffffff00000000;
  uVar21 = 0;
  LOCK();
  *(int *)(lVar11 + 0xb0) = *(int *)(lVar11 + 0xb0) + 1;
  UNLOCK();
  lVar22 = *(longlong *)(lVar11 + 0x50);
  uVar13 = uVar12;
  if (lVar22 == 0) {
    uVar21 = 0xffffff1d;
    lVar22 = 0;
  }
  else {
    LOCK();
    lVar3 = *(longlong *)(lVar11 + 0xb8);
    *(longlong *)(lVar11 + 0xb8) = 0;
    UNLOCK();
    if (lVar3 != 0) {
LAB_18016caf9:
      lVar10 = *(longlong *)(lVar11 + 0x18);
      uVar13 = 0;
      if ((*(uint *)(lVar10 + 0x48) == *(uint *)(lVar10 + 0x50)) ||
         (puVar15 = (uint *)((ulonglong)*(uint *)(lVar10 + 0x48) + lVar10 + 0x40),
         puVar15 == (uint *)0x0)) goto LAB_18016cd51;
      cVar4 = *(char *)((longlong)puVar15 + 3);
      if (cVar4 == 'B') {
        local_68 = *puVar15 & 0xffffff;
        local_50 = (byte *)((longlong)(int)puVar15[1] + (longlong)puVar15);
        local_88 = 0;
        uStack_80 = 0;
        local_78 = 0;
        local_64 = 1;
        local_62 = 4;
        local_70 = 0;
        local_6b = 0;
        local_6c = 0;
        local_69 = 0;
        local_60 = 0x10000;
        local_5c = 1;
        local_58 = 0xffffffffffffffff;
        local_48 = local_68;
        if ((*(byte *)(lVar22 + 0xb0) & 1) != 0) {
          uVar17 = *puVar15 & 0xffffff;
          uVar20 = 0;
LAB_18016cd19:
          local_58 = 0xffffffffffffffff;
          local_5c = 1;
          local_60 = 0x10000;
          local_62 = 4;
          local_64 = 1;
          local_69 = 0;
          local_78 = 0;
          uStack_80 = 0;
          local_88 = 0;
          local_68 = local_48;
          FUN_1801674a0(lVar11,local_50,uVar17,uVar20,&local_62);
        }
LAB_18016cd2a:
        uVar13 = FUN_180169170(lVar22,lVar11,0,&local_88,lVar3);
        if ((int)uVar13 == 4) {
          uVar21 = 0xffffffcc;
LAB_18016cd51:
          LOCK();
          *(longlong *)(lVar11 + 0xb8) = lVar3;
          UNLOCK();
          lVar22 = *(longlong *)(lVar11 + 0x50);
          goto LAB_18016cde6;
        }
      }
      else {
        if (cVar4 == 'd') {
          pbVar16 = (byte *)((longlong)(int)puVar15[1] + (longlong)puVar15);
          uVar17 = (*puVar15 & 0xffffff) - 8;
          if ((7 < (*puVar15 & 0xffffff)) && (bVar5 = *pbVar16, bVar5 - 1 < 6)) {
            bVar6 = pbVar16[4];
            uVar19 = (uint)bVar6;
            if ((0xd < bVar6) && (bVar7 = pbVar16[5], bVar6 < bVar7)) {
              bVar8 = pbVar16[1];
              if (bVar7 < bVar8) {
                if (bVar5 - 1 < 6) {
                  uVar18 = (uint)bVar7;
                  switch(bVar5 - 1) {
                  default:
                    bVar23 = uVar18 - bVar6 < 0x14;
                    break;
                  case 1:
                  case 3:
                    bVar23 = uVar18 - bVar6 < 0x28;
                    break;
                  case 4:
                  case 5:
                    goto switchD_18016cc14_caseD_4;
                  }
                  if (!bVar23) {
LAB_18016cc41:
                    uVar19 = 0x80000000;
                    /* WARNING (jumptable): Sanity check requires truncation of jumptable */
                    /* WARNING: Could not find normalized switch variable to match jumptable */
                    switch(bVar5) {
                    case 0:
                      goto switchD_18016cc14_caseD_4;
                    default:
                      if (0x13 < bVar8 - uVar18) goto LAB_18016cc76;
                      break;
                    case 3:
                    case 4:
                    case 6:
                      if (7 < bVar8 - uVar18) goto LAB_18016cc76;
                    }
                  }
                }
                else {
LAB_18016cc76:
                  if (((((ulonglong)bVar8 < (ulonglong)uVar17) &&
                       (uVar9 = *(ushort *)(pbVar16 + 2),
                       (ulonglong)uVar9 <= (ulonglong)uVar17 - (ulonglong)bVar8)) &&
                      ((bVar5 != 3 || (7 < uVar9)))) && (uVar9 != 0)) {
                    local_78 = 0;
                    local_50 = pbVar16 + 8;
                    local_88 = 0;
                    uStack_80 = 0;
                    local_64 = 1;
                    local_62 = 4;
                    local_70 = *(undefined4 *)pbVar16;
                    local_6c = pbVar16[4];
                    local_6b = *(undefined2 *)(pbVar16 + 5);
                    local_69 = 0;
                    local_60 = 0x10000;
                    local_5c = 1;
                    local_58 = 0xffffffffffffffff;
                    local_68 = uVar17;
                    local_48 = uVar17;
                    if ((*(byte *)(lVar22 + 0xb0) & 1) != 0) {
                      uVar20 = 1;
                      goto LAB_18016cd19;
                    }
                    goto LAB_18016cd2a;
                  }
                }
              }
            }
          }
        }
        else if (cVar4 == 'S') goto LAB_18016cd93;
LAB_18016cd7a:
        *(longlong *)(*(longlong *)(lVar11 + 0x18) + 0x88) =
             *(longlong *)(*(longlong *)(lVar11 + 0x18) + 0x88) + 1;
      }
LAB_18016cd93:
      lVar10 = *(longlong *)(lVar11 + 0x18);
      uVar17 = *(uint *)(lVar10 + 0x48);
      uVar17 = uVar17 + 7 +
               (*(uint *)((ulonglong)uVar17 + 0x40 + lVar10) & 0xffffff) +
               *(int *)((ulonglong)uVar17 + 0x44 + lVar10) & 0xfffffff8;
      if (*(uint *)(lVar10 + 0x44) <= uVar17) {
        uVar17 = *(uint *)(lVar10 + 0x40);
      }
      LOCK();
      *(uint *)(lVar10 + 0x48) = uVar17;
      UNLOCK();
      goto LAB_18016caf9;
    }
    lVar22 = *(longlong *)(lVar11 + 0x50);
    uVar21 = 0xffffff1c;
  }
LAB_18016cde6:
  uVar14 = (undefined4)(uVar13 >> 0x20);
  LOCK();
  piVar1 = (int *)(lVar11 + 0xb0);
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if ((iVar2 == 0x40000001) && (lVar22 != 0)) {
    RTSemEventSignal(*(undefined8 *)(lVar22 + 0x80));
    uVar14 = extraout_var;
  }
  uVar13 = rdtsc();
  uVar12 = (CONCAT44(uVar14,(int)uVar13) | uVar13 & 0xffffffff00000000) - uVar12;
  *(ulonglong *)(*(longlong *)(lVar11 + 0x18) + 0xa8) =
       *(longlong *)(*(longlong *)(lVar11 + 0x18) + 0xa8) + uVar12;
  *(longlong *)(*(longlong *)(lVar11 + 0x18) + 0xa0) =
       *(longlong *)(*(longlong *)(lVar11 + 0x18) + 0xa0) + 1;
  if (*(ulonglong *)(*(longlong *)(lVar11 + 0x18) + 0xb0) < uVar12) {
    *(ulonglong *)(*(longlong *)(lVar11 + 0x18) + 0xb0) = uVar12;
  }
  if (uVar12 < *(ulonglong *)(*(longlong *)(lVar11 + 0x18) + 0xb8)) {
    *(ulonglong *)(*(longlong *)(lVar11 + 0x18) + 0xb8) = uVar12;
  }
  SUPR0ObjRelease(*(undefined8 *)(lVar11 + 0x60),param_2);
  return uVar21;
switchD_18016cc14_caseD_4:
  if (uVar18 - uVar19 < 0x3c) goto LAB_18016cd7a;
  goto LAB_18016cc41;
}

