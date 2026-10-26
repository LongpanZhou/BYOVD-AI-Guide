
/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */

void FUN_18016b930(longlong param_1,longlong param_2,longlong param_3,uint param_4,longlong param_5)

{
  byte bVar1;
  undefined1 auVar2 [16];
  undefined1 auVar3 [16];
  int iVar4;
  uint uVar5;
  undefined8 uVar6;
  longlong lVar7;
  uint uVar8;
  ulonglong uVar9;
  uint uVar10;
  bool bVar11;
  int local_res8 [2];
  int local_98 [2];
  ulonglong local_90;
  undefined8 local_88;
  undefined8 uStack_80;
  undefined8 local_78;
  undefined4 local_70;
  undefined1 local_6c;
  undefined2 local_6b;
  undefined1 local_69;
  int local_68;
  undefined2 local_64;
  undefined2 local_62;
  undefined4 local_60;
  undefined2 local_5c;
  undefined8 local_58;
  longlong local_50;
  int local_48;
  undefined8 local_40;
  longlong local_38;
  int local_30;
  
  if (*(longlong *)(param_1 + 0x68) == 0) {
    return;
  }
  uVar6 = 0;
  if ((*(uint *)(param_2 + 0xb0) & param_4 & 1) != 0) {
    if ((param_4 & 2) != 0) {
      FUN_18016b930();
      param_4 = param_4 & 0xfffffffd;
    }
    if (*(short *)(param_5 + 0x2c) != 1) {
      return;
    }
    if (*(uint *)(param_5 + 0x20) < 0xe) {
      return;
    }
    if (param_3 == 0) {
      return;
    }
    lVar7 = *(longlong *)(param_5 + 0x38);
    *(undefined4 *)(lVar7 + 6) = *(undefined4 *)(param_1 + 0x78);
    *(undefined2 *)(lVar7 + 10) = *(undefined2 *)(param_1 + 0x7c);
    if ((*(ushort *)(param_5 + 0x26) & 8) == 0) {
      uVar6 = 0;
      if (*(short *)(lVar7 + 0xc) == -0x227a) {
        uVar6 = FUN_18016c1b0(param_1,param_3,lVar7,*(undefined4 *)(param_5 + 0x20));
      }
    }
    else {
      iVar4 = nocrt_memcmp(lVar7 + 0x16,param_3,6);
      if (iVar4 == 0) {
        *(undefined4 *)(lVar7 + 0x16) = *(undefined4 *)(param_1 + 0x78);
        *(undefined2 *)(lVar7 + 0x1a) = *(undefined2 *)(param_1 + 0x7c);
      }
      uVar6 = nocrt_memcmp(lVar7 + 0x20,param_3,6);
      if ((int)uVar6 == 0) {
        *(undefined4 *)(lVar7 + 0x20) = *(undefined4 *)(param_1 + 0x78);
        uVar6 = 0;
        *(undefined2 *)(lVar7 + 0x24) = *(undefined2 *)(param_1 + 0x7c);
      }
    }
  }
  uVar9 = rdtsc();
  bVar1 = *(byte *)(param_5 + 0x18);
  local_90 = CONCAT44((int)((ulonglong)uVar6 >> 0x20),(int)uVar9) | uVar9 & 0xffffffff00000000;
  if (bVar1 == 0) {
LAB_18016bbc1:
    lVar7 = (**(code **)(*(longlong *)(param_1 + 0x68) + 0x48))
                      (*(longlong *)(param_1 + 0x68),*(undefined8 *)(param_3 + 0xc0),param_5,param_4
                      );
  }
  else {
    if (bVar1 < 0x20) {
      uVar8 = 1 << (bVar1 & 0x1f);
      if (param_4 == 2) {
        bVar11 = (*(uint *)(param_1 + 0x8c) & uVar8) == 0;
      }
      else if (param_4 == 1) {
        bVar11 = (*(uint *)(param_1 + 0x88) & uVar8) == 0;
      }
      else {
        bVar11 = (uVar8 & *(uint *)(param_1 + 0x8c) & *(uint *)(param_1 + 0x88)) == 0;
      }
      if (!bVar11) goto LAB_18016bbc1;
    }
    lVar7 = 0;
    if (*(short *)(param_5 + 0x2c) == 1) {
      uVar9 = CONCAT62(0,*(ushort *)(param_5 + 0x1a));
      uVar10 = 0;
      auVar2._8_8_ = 0;
      auVar2._0_8_ = uVar9;
      auVar3._8_8_ = 0;
      auVar3._0_8_ = (uVar9 - 1) +
                     ((ulonglong)*(uint *)(param_5 + 0x20) - (ulonglong)*(byte *)(param_5 + 0x1e));
      lVar7 = SUB168(auVar3 / auVar2,0);
      uVar8 = SUB164(auVar3 / auVar2,0);
      if (uVar8 != 0) {
        do {
          uVar5 = FUN_1801661f0(param_5 + 0x18,*(undefined8 *)(param_5 + 0x38),
                                *(undefined4 *)(param_5 + 0x20),uVar10,uVar8,param_3 + 200,
                                local_res8,local_98);
          local_78 = 0;
          local_88 = 0;
          uStack_80 = 0;
          local_38 = (ulonglong)uVar5 + *(longlong *)(param_5 + 0x38);
          local_68 = local_res8[0] + local_98[0];
          local_64 = 1;
          local_62 = 4;
          local_5c = 2;
          local_50 = param_3 + 200;
          local_70 = 0;
          local_6b = 0;
          local_6c = 0;
          local_69 = 0;
          local_48 = local_res8[0];
          local_30 = local_98[0];
          local_60 = 0x20000;
          local_58 = 0xffffffffffffffff;
          local_40 = 0xffffffffffffffff;
          lVar7 = (**(code **)(*(longlong *)(param_1 + 0x68) + 0x48))
                            (*(longlong *)(param_1 + 0x68),*(undefined8 *)(param_3 + 0xc0),&local_88
                             ,param_4);
          if ((int)lVar7 < 0) break;
          uVar10 = uVar10 + 1;
          lVar7 = param_3 + 200;
        } while (uVar10 < uVar8);
      }
    }
  }
  uVar9 = rdtsc();
  local_90 = (CONCAT44((int)((ulonglong)lVar7 >> 0x20),(int)uVar9) | uVar9 & 0xffffffff00000000) -
             local_90;
  *(ulonglong *)(*(longlong *)(param_3 + 0x18) + 200) =
       *(longlong *)(*(longlong *)(param_3 + 0x18) + 200) + local_90;
  *(longlong *)(*(longlong *)(param_3 + 0x18) + 0xc0) =
       *(longlong *)(*(longlong *)(param_3 + 0x18) + 0xc0) + 1;
  if (*(ulonglong *)(*(longlong *)(param_3 + 0x18) + 0xd0) < local_90) {
    *(ulonglong *)(*(longlong *)(param_3 + 0x18) + 0xd0) = local_90;
  }
  if (local_90 < *(ulonglong *)(*(longlong *)(param_3 + 0x18) + 0xd8)) {
    *(ulonglong *)(*(longlong *)(param_3 + 0x18) + 0xd8) = local_90;
  }
  return;
}

