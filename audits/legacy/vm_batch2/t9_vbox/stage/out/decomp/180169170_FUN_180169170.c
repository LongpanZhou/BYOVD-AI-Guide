
int FUN_180169170(longlong param_1,undefined4 *param_2,uint param_3,longlong param_4,uint *param_5)

{
  uint *puVar1;
  int *piVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  undefined8 *puVar5;
  longlong lVar6;
  char cVar7;
  int iVar8;
  uint uVar9;
  ulonglong uVar10;
  uint *puVar11;
  short local_res20 [4];
  undefined4 local_48;
  byte local_40;
  undefined1 uStack_3f;
  undefined1 uStack_3e;
  byte bStack_3d;
  undefined1 uStack_3c;
  undefined1 uStack_3b;
  byte bStack_3a;
  undefined1 uStack_39;
  undefined2 uStack_38;
  undefined2 uStack_36;
  short local_34;
  char local_30 [24];
  
  if (*(uint *)(param_4 + 0x20) < 0xe) {
    return 0;
  }
  if (*(uint *)(param_4 + 0x40) < 0xe) {
    cVar7 = FUN_18016aca0(param_4,0,0xe,&local_40);
    if (cVar7 == '\0') {
      return 0;
    }
  }
  else {
    puVar5 = *(undefined8 **)(param_4 + 0x38);
    uVar4 = *puVar5;
    local_40 = (byte)uVar4;
    uStack_3f = (undefined1)((ulonglong)uVar4 >> 8);
    uStack_3e = (undefined1)((ulonglong)uVar4 >> 0x10);
    bStack_3d = (byte)((ulonglong)uVar4 >> 0x18);
    uStack_3c = (undefined1)((ulonglong)uVar4 >> 0x20);
    uStack_3b = (undefined1)((ulonglong)uVar4 >> 0x28);
    bStack_3a = (byte)((ulonglong)uVar4 >> 0x30);
    uStack_39 = (undefined1)((ulonglong)uVar4 >> 0x38);
    uStack_38 = (undefined2)*(undefined4 *)(puVar5 + 1);
    uStack_36 = (undefined2)((uint)*(undefined4 *)(puVar5 + 1) >> 0x10);
    local_34 = *(short *)((longlong)puVar5 + 0xc);
  }
  if ((((param_2 != (undefined4 *)0x0) && (*(char *)((longlong)param_2 + 6) == '\0')) &&
      (iVar8 = nocrt_memcmp(&bStack_3a,param_2,6), iVar8 != 0)) && ((bStack_3a & 1) == 0)) {
    RTSpinlockAcquire(*(undefined8 *)(param_1 + 8));
    uVar10 = (ulonglong)*(uint *)(param_1 + 0x10);
    if (*(uint *)(param_1 + 0x10) != 0) {
      do {
        uVar9 = (int)uVar10 - 1;
        uVar10 = (ulonglong)uVar9;
        if (*(undefined4 **)(*(longlong *)(param_1 + 0x18) + 0x10 + uVar10 * 0x18) == param_2) {
          puVar3 = (undefined4 *)(*(longlong *)(param_1 + 0x18) + uVar10 * 0x18);
          if (puVar3 != (undefined4 *)0x0) {
            *puVar3 = CONCAT22(uStack_38,CONCAT11(uStack_39,bStack_3a));
            *(undefined2 *)(puVar3 + 1) = uStack_36;
          }
          break;
        }
      } while (uVar9 != 0);
    }
    *param_2 = CONCAT22(uStack_38,CONCAT11(uStack_39,bStack_3a));
    *(undefined2 *)(param_2 + 1) = uStack_36;
    RTSpinlockRelease(*(undefined8 *)(param_1 + 8));
  }
  if ((*(byte *)(param_1 + 0xb0) & 1) == 0) {
    if ((local_40 & 1) != 0) {
      iVar8 = FUN_18016a090(param_1,param_3,param_2,param_5);
      goto LAB_1801693f4;
    }
  }
  else {
    if ((local_40 & 1) != 0) {
LAB_180169282:
      iVar8 = FUN_180169650(param_1,param_3,param_2,param_4,&local_40,param_5);
      goto LAB_1801693f4;
    }
    if ((param_3 & 1) != 0) {
      if (local_34 == 8) {
        cVar7 = FUN_18016aca0(param_4,0x1e,4,&local_48);
        if (cVar7 != '\0') {
          if (local_48 == -1) goto LAB_18016936c;
          if (((byte)local_48 & 0xf0) == 0xe0) {
            bStack_3d = local_48._1_1_ & 0x7f;
            local_40 = 1;
            uStack_3f = 0;
            uStack_3c = local_48._2_1_;
            uStack_3b = local_48._3_1_;
            uStack_3e = 0x5e;
            goto LAB_1801693a5;
          }
        }
      }
      else if (local_34 == 0x608) {
        cVar7 = FUN_18016aca0(param_4,0x14,2,local_res20);
        if ((cVar7 != '\0') && (local_res20[0] == 0x100)) {
LAB_18016936c:
          local_40 = 0xff;
          uStack_3f = 0xff;
          uStack_3e = 0xff;
          bStack_3d = 0xff;
          uStack_3c = 0xff;
          uStack_3b = 0xff;
          goto LAB_1801693a5;
        }
      }
      else if (((local_34 == -0x227a) &&
               (cVar7 = FUN_18016aca0(param_4,0x26,0x10,local_30), cVar7 != '\0')) &&
              (local_30[0] == -1)) {
        local_40 = 0x33;
        uStack_3f = 0x33;
        uStack_3e = (undefined1)local_30._12_2_;
        bStack_3d = SUB21(local_30._12_2_,1);
        uStack_3c = (undefined1)local_30._14_2_;
        uStack_3b = SUB21(local_30._14_2_,1);
LAB_1801693a5:
        FUN_18016adc0(param_4,0,6,&local_40);
        goto LAB_180169282;
      }
      iVar8 = FUN_1801697d0(param_1,param_4,&local_40,param_5);
      goto LAB_1801693f4;
    }
  }
  iVar8 = FUN_18016a630(param_1,param_3,param_2,&local_40,param_5);
LAB_1801693f4:
  if (iVar8 != 4) {
    if (((param_2 == (undefined4 *)0x0) || (uVar9 = *param_5, uVar9 == 0)) ||
       (((*(longlong *)(param_5 + 2) != 0 &&
         ((*(uint *)(*(longlong *)(param_5 + 2) + 0x84) & uVar9) == uVar9)) ||
        (cVar7 = RTThreadPreemptIsEnabled(0), cVar7 != '\0')))) {
      FUN_180168320(param_1,param_5,param_4,param_2);
    }
    else {
      if (*param_5 != 0) {
        if (*(longlong *)(param_5 + 2) != 0) {
          LOCK();
          piVar2 = (int *)(*(longlong *)(param_5 + 2) + 0x80);
          iVar8 = *piVar2;
          *piVar2 = *piVar2 + -1;
          UNLOCK();
          if (iVar8 == 0x40000001) {
            RTSemEventSignal(*(undefined8 *)(param_1 + 0x80));
          }
        }
        param_5[2] = 0;
        param_5[3] = 0;
        *param_5 = 0;
      }
      uVar9 = param_5[4];
      if (uVar9 != 0) {
        puVar11 = param_5 + (ulonglong)uVar9 * 4 + 6;
        do {
          puVar1 = puVar11 + -4;
          puVar11 = puVar11 + -4;
          uVar9 = uVar9 - 1;
          lVar6 = *(longlong *)(*(longlong *)puVar1 + 0x50);
          LOCK();
          piVar2 = (int *)(*(longlong *)puVar1 + 0xb0);
          iVar8 = *piVar2;
          *piVar2 = *piVar2 + -1;
          UNLOCK();
          if ((iVar8 == 0x40000001) && (lVar6 != 0)) {
            RTSemEventSignal(*(undefined8 *)(lVar6 + 0x80));
          }
          puVar11[0] = 0;
          puVar11[1] = 0;
        } while (uVar9 != 0);
      }
      param_5[4] = 0;
      iVar8 = 4;
    }
  }
  return iVar8;
}

