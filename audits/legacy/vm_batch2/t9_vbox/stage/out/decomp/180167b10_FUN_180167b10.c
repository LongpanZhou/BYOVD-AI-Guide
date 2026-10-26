
/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */

ulonglong FUN_180167b10(longlong param_1,undefined8 param_2,uint param_3,uint param_4,uint param_5,
                       undefined8 param_6,undefined8 param_7,undefined4 *param_8)

{
  int *piVar1;
  byte bVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  char cVar5;
  byte bVar6;
  uint uVar7;
  ulonglong uVar8;
  undefined4 *_Dst;
  longlong lVar9;
  ulonglong uVar10;
  int iVar11;
  uint uVar12;
  char *pcVar13;
  undefined8 *puVar14;
  uint uVar15;
  uint uVar16;
  longlong lVar17;
  
  uVar7 = param_5 | 0x4000;
  if ((param_5 & 0xc000) != 0) {
    uVar7 = param_5;
  }
  uVar16 = uVar7 | 0x10000;
  if ((uVar7 & 0x30000) != 0) {
    uVar16 = uVar7;
  }
  uVar8 = FUN_180168ce0();
  uVar10 = uVar8 & 0xffffffff;
  if ((int)uVar8 < 0) {
    return uVar8;
  }
  _Dst = (undefined4 *)
         RTMemAllocZTag(0x1c8,
                        "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp");
  if (_Dst == (undefined4 *)0x0) {
    return 0xfffffff8;
  }
  memset(_Dst,0xff,6);
  _Dst[3] = uVar16;
  *(undefined8 *)(_Dst + 0xe) = 0;
  _Dst[0x11] = 0;
  pcVar13 = (char *)((longlong)_Dst + 0x82);
  *(undefined8 *)(_Dst + 0x16) = param_2;
  iVar11 = 1;
  *(undefined8 *)(_Dst + 0x12) = 0xffffffffffffffff;
  *(longlong *)(_Dst + 0x14) = param_1;
  *(undefined8 *)(_Dst + 0x2a) = 0;
  _Dst[0x2c] = 0;
  do {
    lVar17 = 3;
    if ((int)uVar10 < 0) goto LAB_180167f4e;
    bVar2 = *(byte *)(param_1 + 0xb0);
    pcVar13[-2] = '\0';
    if (iVar11 == 1) {
      cVar5 = '\x04';
    }
    else if (iVar11 == 2) {
      cVar5 = '\x10';
    }
    else if (iVar11 == 3) {
      cVar5 = '\n';
    }
    else {
      cVar5 = '\0';
    }
    *pcVar13 = cVar5;
    bVar6 = cVar5 + 3U & 0xfc;
    pcVar13[1] = bVar6;
    if ((bVar2 & 1) == 0) {
      pcVar13[-1] = '\0';
      pcVar13[-10] = '\0';
      pcVar13[-9] = '\0';
      pcVar13[-8] = '\0';
      pcVar13[-7] = '\0';
      pcVar13[-6] = '\0';
      pcVar13[-5] = '\0';
      pcVar13[-4] = '\0';
      pcVar13[-3] = '\0';
LAB_180167c8b:
      uVar10 = 0;
    }
    else {
      pcVar13[-1] = ' ';
      lVar9 = RTMemAllocZTag((ulonglong)bVar6 << 5,
                             "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp"
                            );
      *(longlong *)(pcVar13 + -10) = lVar9;
      if (lVar9 != 0) goto LAB_180167c8b;
      uVar10 = 0xfffffff8;
    }
    iVar11 = iVar11 + 1;
    pcVar13 = pcVar13 + 0x10;
  } while (iVar11 < 4);
  if (-1 < (int)uVar10) {
    lVar9 = RTMemAllocTag((ulonglong)*(uint *)(param_1 + 0x14) * 0x10 + 0x18,
                          "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp");
    *(longlong *)(_Dst + 0x2e) = lVar9;
    if (lVar9 == 0) {
      uVar10 = 0xfffffff8;
    }
    else {
      uVar7 = RTSemEventCreate(_Dst + 0xe);
      uVar10 = (ulonglong)uVar7;
      if (-1 < (int)uVar7) {
        uVar7 = RTSpinlockCreate(_Dst + 0x2a,2,"hRecvInSpinlock");
        uVar10 = (ulonglong)uVar7;
        if (-1 < (int)uVar7) {
          if (param_4 < 0x20) {
            param_4 = 0x20;
          }
          uVar16 = param_4 + 7 & 0xfffffff8;
          uVar7 = 0x20;
          if (0x1f < param_3) {
            uVar7 = param_3;
          }
          uVar15 = uVar7 + 7 & 0xfffffff8;
          uVar12 = uVar16 + 0x140 + uVar15;
          uVar7 = SUPR0MemAlloc(*(undefined8 *)(_Dst + 0x16),uVar12,_Dst + 10,_Dst + 0xc);
          uVar10 = (ulonglong)uVar7;
          if (-1 < (int)uVar7) {
            puVar14 = *(undefined8 **)(_Dst + 10);
            for (uVar8 = (ulonglong)(uVar12 >> 3); uVar8 != 0; uVar8 = uVar8 - 1) {
              *puVar14 = 0;
              puVar14 = puVar14 + 1;
            }
            puVar3 = *(undefined4 **)(_Dst + 10);
            *(undefined8 *)(_Dst + 8) = *(undefined8 *)(_Dst + 0xc);
            *(undefined4 **)(_Dst + 6) = puVar3;
            puVar3[1] = uVar16 + 0x140 + uVar15;
            puVar3[2] = uVar15;
            *puVar3 = 0x19110919;
            puVar3[3] = uVar16;
            puVar3[4] = 0x130;
            puVar3[5] = uVar16 + 0x130;
            iVar11 = uVar16 + 0x100;
            puVar3[6] = 0x130;
            puVar3[9] = 0x130;
            puVar3[0x10] = iVar11;
            puVar3[8] = 0x130;
            puVar3[0x12] = iVar11;
            puVar3[0x14] = iVar11;
            puVar3[0x15] = iVar11;
            puVar3[0x11] = iVar11 + uVar15;
            lVar9 = SUPR0ObjRegister(param_2,3,FUN_180167190,_Dst,*(undefined8 *)(param_1 + 0x88));
            *(longlong *)(_Dst + 0x18) = lVar9;
            if (lVar9 != 0) {
              uVar7 = RTHandleTableAllocWithCtx
                                (*(undefined8 *)(*(longlong *)(param_1 + 0x88) + 0x18),_Dst,param_2,
                                 _Dst + 0x11);
              uVar8 = (ulonglong)uVar7;
              if (-1 < (int)uVar7) {
                RTSpinlockAcquire(*(undefined8 *)(param_1 + 8));
                uVar7 = *(uint *)(param_1 + 0x10);
                uVar10 = (ulonglong)uVar7;
                lVar17 = *(longlong *)(param_1 + 0x18);
                *(undefined4 *)(lVar17 + uVar10 * 0x18) = *_Dst;
                *(undefined2 *)(lVar17 + 4 + uVar10 * 0x18) = *(undefined2 *)(_Dst + 1);
                *(undefined1 *)(*(longlong *)(param_1 + 0x18) + 8 + uVar10 * 0x18) = 0;
                *(undefined1 *)(*(longlong *)(param_1 + 0x18) + 6 + uVar10 * 0x18) = 0;
                *(undefined1 *)(*(longlong *)(param_1 + 0x18) + 7 + uVar10 * 0x18) = 0;
                *(undefined4 **)(*(longlong *)(param_1 + 0x18) + 0x10 + uVar10 * 0x18) = _Dst;
                *(uint *)(param_1 + 0x10) = uVar7 + 1;
                *(longlong *)(_Dst + 0x14) = param_1;
                lVar17 = *(longlong *)(param_1 + 0x38);
                if (lVar17 == 0) {
                  RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
                }
                else {
                  LOCK();
                  *(int *)(lVar17 + 0x80) = *(int *)(lVar17 + 0x80) + 1;
                  UNLOCK();
                  RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
                  lVar9 = *(longlong *)(lVar17 + 0x68);
                  if (lVar9 != 0) {
                    uVar7 = (**(code **)(lVar9 + 0x30))(lVar9,_Dst,_Dst + 0x30);
                    uVar8 = (ulonglong)uVar7;
                  }
                  LOCK();
                  piVar1 = (int *)(lVar17 + 0x80);
                  iVar11 = *piVar1;
                  *piVar1 = *piVar1 + -1;
                  UNLOCK();
                  if ((iVar11 == 0x40000001) && (*(longlong *)(lVar17 + 0x70) != 0)) {
                    RTSemEventSignal(*(undefined8 *)(*(longlong *)(lVar17 + 0x70) + 0x80));
                  }
                  if ((int)uVar8 < 0) goto LAB_180167ee6;
                }
                *param_8 = _Dst[0x11];
                return 0;
              }
LAB_180167ee6:
              SUPR0ObjAddRef(*(undefined8 *)(param_1 + 0x90),param_2);
              SUPR0ObjRelease(*(undefined8 *)(_Dst + 0x18),param_2);
              return uVar8;
            }
            SUPR0MemFree(*(undefined8 *)(_Dst + 0x16),*(undefined8 *)(_Dst + 10));
            *(undefined8 *)(_Dst + 10) = 0;
            *(undefined8 *)(_Dst + 6) = 0;
          }
        }
      }
    }
  }
LAB_180167f4e:
  RTSpinlockDestroy(*(undefined8 *)(_Dst + 0x2a));
  *(undefined8 *)(_Dst + 0x2a) = 0;
  RTSemEventDestroy(*(undefined8 *)(_Dst + 0xe));
  *(undefined8 *)(_Dst + 0xe) = 0;
  RTMemFree(*(undefined8 *)(_Dst + 0x2e));
  puVar14 = (undefined8 *)(_Dst + 0x1e);
  do {
    uVar4 = *puVar14;
    *puVar14 = 0;
    *(undefined2 *)(puVar14 + 1) = 0;
    RTMemFree(uVar4);
    puVar14 = puVar14 + 2;
    lVar17 = lVar17 + -1;
  } while (lVar17 != 0);
  RTMemFree(_Dst);
  return uVar10;
}

