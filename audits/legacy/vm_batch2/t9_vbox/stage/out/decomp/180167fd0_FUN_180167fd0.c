
/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */

ulonglong FUN_180167fd0(longlong param_1,undefined8 param_2)

{
  int iVar1;
  undefined1 uVar2;
  uint uVar3;
  undefined4 *puVar4;
  longlong lVar5;
  longlong lVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  longlong *plVar10;
  uint uVar11;
  longlong *local_res8;
  undefined8 local_res10;
  char *local_res18;
  
  iVar1 = *(int *)(param_1 + 0x140);
  if ((iVar1 == 1) || (iVar1 == 2)) {
LAB_180168305:
    uVar7 = 0;
  }
  else {
    if (iVar1 == 3) {
      local_res18 = "VBoxNetFlt";
    }
    else {
      if (iVar1 != 4) {
        if (iVar1 != 5) {
          return 0xfffffff4;
        }
        goto LAB_180168305;
      }
      local_res18 = "VBoxNetAdp";
    }
    local_res10 = param_2;
    uVar3 = RTMpGetCount();
    puVar4 = (undefined4 *)
             RTMemAllocZTag((ulonglong)uVar3 * 8 + 0xb0,
                            "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp")
    ;
    if (puVar4 == (undefined4 *)0x0) {
      return 0xfffffff8;
    }
    uVar8 = 0;
    puVar4[0x26] = uVar3;
    uVar7 = uVar8;
    if (uVar3 != 0) {
      plVar10 = (longlong *)(puVar4 + 0x2c);
      uVar9 = uVar8;
      do {
        if ((int)uVar7 < 0) break;
        lVar5 = RTMemAllocTag((ulonglong)*(uint *)(param_1 + 0x14) * 0x10 + 0x18,
                              "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp"
                             );
        *plVar10 = lVar5;
        uVar7 = uVar8;
        if (lVar5 == 0) {
          uVar7 = 0xfffffff8;
        }
        uVar11 = (int)uVar9 + 1;
        uVar9 = (ulonglong)uVar11;
        plVar10 = plVar10 + 1;
      } while (uVar11 < uVar3);
    }
    plVar10 = (longlong *)(puVar4 + 0x28);
    uVar9 = uVar8;
    local_res8 = plVar10;
    do {
      lVar5 = 2;
      if ((int)uVar7 < 0) goto LAB_1801682c0;
      lVar6 = RTMemAllocTag((ulonglong)*(uint *)(param_1 + 0x14) * 0x10 + 0x18,
                            "D:\\tinderboxa\\win-7.0\\src\\VBox\\Devices\\Network\\SrvIntNetR0.cpp")
      ;
      uVar7 = uVar8;
      if (lVar6 == 0) {
        uVar7 = 0xfffffff8;
      }
      uVar3 = (int)uVar9 + 1;
      uVar9 = (ulonglong)uVar3;
      *local_res8 = lVar6;
      local_res8 = local_res8 + 1;
    } while (uVar3 < 2);
    if (-1 < (int)uVar7) {
      *puVar4 = 0xa2cdf004;
      *(code **)(puVar4 + 2) = FUN_18016b280;
      *(code **)(puVar4 + 4) = FUN_18016b410;
      *(code **)(puVar4 + 6) = FUN_18016b8b0;
      *(code **)(puVar4 + 8) = FUN_18016b850;
      *(code **)(puVar4 + 10) = FUN_18016b910;
      *(code **)(puVar4 + 0xc) = FUN_18016b6d0;
      *(code **)(puVar4 + 0xe) = FUN_18016b7a0;
      *(code **)(puVar4 + 0x10) = FUN_18016b6b0;
      *(code **)(puVar4 + 0x12) = FUN_18016b790;
      if ((*(byte *)(param_1 + 0xb0) & 1) != 0) {
        *(code **)(puVar4 + 0x14) = FUN_180168f30;
      }
      puVar4[0x1e] = 0xffffffff;
      *(undefined2 *)(puVar4 + 0x1f) = 0xffff;
      *(code **)(puVar4 + 0x16) = FUN_18016b140;
      puVar4[0x18] = 0xa2cdf004;
      *(longlong *)(puVar4 + 0x1c) = param_1;
      *(undefined8 *)(puVar4 + 0x24) = 0;
      uVar3 = RTSpinlockCreate(puVar4 + 0x24,2,"hDstTabSpinlock");
      if (-1 < (int)uVar3) {
        uVar3 = *(uint *)(param_1 + 0xb0);
        *(undefined4 **)(param_1 + 0x38) = puVar4;
        *(undefined4 *)(param_1 + 0x28) = puVar4[0x1e];
        *(undefined2 *)(param_1 + 0x2c) = *(undefined2 *)(puVar4 + 0x1f);
        *(undefined2 *)(param_1 + 0x2f) = 0;
        *(bool *)(param_1 + 0x2e) = (uVar3 & 0x400200) == 0x400200;
        *(byte *)(param_1 + 0x32) = (byte)(uVar3 >> 0x1a) & 1;
        if (((uVar3 >> 0x1a & 1) == 0) || ((uVar3 >> 0xb & 1) == 0)) {
          uVar2 = 0;
        }
        else {
          uVar2 = 1;
        }
        *(undefined1 *)(param_1 + 0x31) = uVar2;
        *(undefined1 *)(param_1 + 0x33) = 0;
        local_res8 = (longlong *)0x0;
        uVar3 = SUPR0ComponentQueryFactory
                          (local_res10,local_res18,"de504d93-1d1e-4781-8b73-6ea39a0e36a2",
                           &local_res8);
        if (-1 < (int)uVar3) {
          uVar3 = (*(code *)local_res8[1])
                            (local_res8,param_1 + 0x144,puVar4,*(uint *)(param_1 + 0xb0) & 1,
                             puVar4 + 0x1a);
          (*(code *)*local_res8)();
          if (-1 < (int)uVar3) goto LAB_180168305;
        }
        *(undefined8 *)(param_1 + 0x38) = 0;
      }
      uVar7 = (ulonglong)uVar3;
      RTSpinlockDestroy(*(undefined8 *)(puVar4 + 0x24));
    }
LAB_1801682c0:
    do {
      RTMemFree(*plVar10);
      plVar10 = plVar10 + 1;
      lVar5 = lVar5 + -1;
    } while (lVar5 != 0);
    if (puVar4[0x26] != 0) {
      do {
        RTMemFree(*(undefined8 *)(puVar4 + uVar8 * 2 + 0x2c));
        uVar3 = (int)uVar8 + 1;
        uVar8 = (ulonglong)uVar3;
      } while (uVar3 < (uint)puVar4[0x26]);
    }
    RTMemFree(puVar4);
  }
  return uVar7;
}

