
ulonglong FUN_180168ce0(longlong param_1)

{
  undefined8 *puVar1;
  longlong *plVar2;
  undefined4 *puVar3;
  uint uVar4;
  longlong lVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  longlong lVar9;
  longlong lVar10;
  undefined8 *puVar11;
  longlong *plVar12;
  uint uVar13;
  ulonglong uVar15;
  bool bVar16;
  ulonglong uVar14;
  
  uVar15 = 0;
  uVar4 = *(uint *)(param_1 + 0x14);
  uVar13 = *(uint *)(param_1 + 0x10);
  if (uVar4 < uVar13) {
    return 0xffffff1e;
  }
  if (uVar4 < uVar13 + 1) {
    uVar4 = uVar4 + 1;
    if (uVar4 < 0x411) {
      if (uVar13 != 0) {
        uVar14 = uVar15;
LAB_180168d50:
        lVar10 = *(longlong *)(*(longlong *)(param_1 + 0x18) + 0x10 + uVar14 * 0x18);
        lVar9 = RTMemAllocTag((ulonglong)uVar4 * 0x10 + 0x18,
                              "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp"
                             );
        if (lVar9 != 0) {
          do {
            lVar5 = *(longlong *)(lVar10 + 0xb8);
            if (lVar5 != 0) {
              LOCK();
              bVar16 = lVar5 == *(longlong *)(lVar10 + 0xb8);
              if (bVar16) {
                *(longlong *)(lVar10 + 0xb8) = lVar9;
              }
              UNLOCK();
              if (bVar16) goto LAB_180168dab;
            }
            FUN_180166940(param_1,lVar10 + 0xb0);
          } while( true );
        }
        goto LAB_180168ede;
      }
LAB_180168db7:
      lVar10 = *(longlong *)(param_1 + 0x38);
      if (lVar10 != 0) {
        plVar12 = (longlong *)(lVar10 + 0xa0);
        plVar2 = (longlong *)(lVar10 + ((ulonglong)*(uint *)(lVar10 + 0x98) + 0x16) * 8);
        if (plVar12 != plVar2) {
          do {
            lVar9 = RTMemAllocTag((ulonglong)uVar4 * 0x10 + 0x18,
                                  "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp"
                                 );
            if (lVar9 == 0) goto LAB_180168ede;
            while( true ) {
              RTSpinlockAcquire(*(undefined8 *)(lVar10 + 0x90));
              lVar5 = *plVar12;
              if (lVar5 != 0) {
                *plVar12 = lVar9;
              }
              RTSpinlockRelease(*(undefined8 *)(lVar10 + 0x90));
              if (lVar5 != 0) break;
              FUN_180166940(param_1,lVar10 + 0x80);
            }
            RTMemFree(lVar5);
            plVar12 = plVar12 + 1;
          } while (plVar12 != plVar2);
        }
      }
      lVar10 = RTMemAllocTag((ulonglong)uVar4 * 0x18,
                             "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp"
                            );
      if (lVar10 == 0) {
LAB_180168ede:
        uVar15 = 0xfffffff8;
      }
      else {
        RTSpinlockAcquire(*(undefined8 *)(param_1 + 8));
        uVar14 = (ulonglong)*(uint *)(param_1 + 0x10);
        lVar9 = *(longlong *)(param_1 + 0x18);
        if (*(uint *)(param_1 + 0x10) != 0) {
          puVar11 = (undefined8 *)(lVar9 + uVar14 * 0x18 + 0x10);
          do {
            puVar1 = puVar11 + -3;
            uVar6 = *(undefined4 *)((longlong)puVar11 + -0x24);
            uVar7 = *(undefined4 *)(puVar11 + -4);
            uVar8 = *(undefined4 *)((longlong)puVar11 + -0x1c);
            puVar3 = (undefined4 *)((lVar10 - lVar9) + -0x10 + (longlong)puVar1);
            *puVar3 = *(undefined4 *)(puVar11 + -5);
            puVar3[1] = uVar6;
            puVar3[2] = uVar7;
            puVar3[3] = uVar8;
            *(undefined8 *)((lVar10 - lVar9) + (longlong)puVar1) = *puVar1;
            *(undefined1 *)(puVar11 + -4) = 0;
            *puVar1 = 0;
            uVar13 = (int)uVar14 - 1;
            uVar14 = (ulonglong)uVar13;
            puVar11 = puVar1;
          } while (uVar13 != 0);
        }
        *(longlong *)(param_1 + 0x18) = lVar10;
        *(uint *)(param_1 + 0x14) = uVar4;
        RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
        RTMemFree(lVar9);
      }
    }
    else {
      uVar15 = 0xffffffca;
    }
  }
  return uVar15;
LAB_180168dab:
  RTMemFree();
  uVar13 = (int)uVar14 + 1;
  uVar14 = (ulonglong)uVar13;
  if (*(uint *)(param_1 + 0x10) <= uVar13) goto LAB_180168db7;
  goto LAB_180168d50;
}

