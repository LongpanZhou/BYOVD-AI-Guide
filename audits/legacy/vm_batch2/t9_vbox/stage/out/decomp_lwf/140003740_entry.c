
/* WARNING: Removing unreachable block (ram,0x000140003845) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulonglong entry(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  undefined *puVar5;
  char *pcVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  undefined8 *puVar9;
  undefined8 local_248;
  undefined1 *local_240;
  undefined1 *local_238;
  code **local_230;
  undefined8 local_228;
  undefined8 uStack_220;
  undefined8 local_218;
  undefined4 local_208;
  undefined2 local_204;
  undefined8 local_202;
  undefined2 local_1fa;
  undefined8 local_1f8;
  undefined8 uStack_1f0;
  undefined4 local_1e8;
  undefined4 uStack_1e4;
  undefined4 uStack_1e0;
  undefined4 uStack_1dc;
  undefined4 local_1d8;
  undefined4 uStack_1d4;
  undefined4 uStack_1d0;
  undefined4 uStack_1cc;
  undefined8 local_1c8;
  undefined8 uStack_1c0;
  code *local_1b8;
  code *local_1b0;
  code *local_1a8;
  code *local_1a0;
  code *local_198;
  code *local_190;
  undefined8 local_188;
  code *local_180;
  code *local_178;
  code *local_170;
  code *local_168;
  undefined8 local_160;
  undefined8 uStack_158;
  undefined8 local_150;
  code *local_148;
  undefined8 local_138;
  undefined8 uStack_130;
  undefined4 local_128;
  undefined4 uStack_124;
  undefined4 uStack_120;
  undefined4 uStack_11c;
  undefined4 local_118;
  undefined4 uStack_114;
  undefined4 uStack_110;
  undefined4 uStack_10c;
  undefined1 local_108 [16];
  undefined1 local_f8 [16];
  code *local_e8 [2];
  code *local_d8;
  code *local_78;
  code *local_58;
  
  uVar3 = RTR0Init(0,param_2,param_3,param_4);
  if (-1 < (int)uVar3) {
    puVar5 = &DAT_1400341a0;
    _DAT_1400341a0 = 0;
    uRam00000001400341a8 = 0;
    _DAT_140034220 = 0;
    _DAT_1400341b0 = 0;
    uRam00000001400341b8 = 0;
    _DAT_1400341c0 = 0;
    uRam00000001400341c8 = 0;
    _DAT_1400341d0 = 0;
    uRam00000001400341d8 = 0;
    _DAT_1400341e0 = 0;
    uRam00000001400341e8 = 0;
    _DAT_1400341f0 = 0;
    uRam00000001400341f8 = 0;
    _DAT_140034200 = 0;
    uRam0000000140034208 = 0;
    _DAT_140034210 = 0;
    uRam0000000140034218 = 0;
    iVar1 = FUN_1400012d0((undefined8 *)&DAT_1400341a0);
    if (-1 < iVar1) {
      DAT_140034178 = &DAT_140034178;
      _DAT_140034180 = &DAT_140034178;
      DAT_140034150 = 0;
      DAT_140034158 = 0;
      DAT_140034160 = (char *)0x0;
      _DAT_140034170 = 0;
      DAT_140034190 = 0;
      _DAT_140034168 = 0;
      LOCK();
      _DAT_140034188 = 1;
      UNLOCK();
      iVar1 = PsCreateSystemThread(&DAT_140034190,0x1fffff,0,0,0,FUN_1400027e0,&DAT_140034150);
      if (iVar1 != 0) {
        DbgPrint("vboxNetLwfWinStartInitIdcThread: IDC initialization failed (system thread creation, status=0x%x)\n"
                 ,iVar1);
        LOCK();
        _DAT_140034188 = _DAT_140034188 & 0xffffffff00000000;
        UNLOCK();
      }
      RTErrConvertFromNtStatus(iVar1);
      RtlInitUnicodeString(&local_138,L"VirtualBox NDIS Light-Weight Filter");
      RtlInitUnicodeString(&local_128,L"{7af6b074-048d-4444-bfce-1ecc8bc5cb76}");
      RtlInitUnicodeString(&local_118,L"VBoxNetLwf");
      local_208 = 0xc8018b;
      local_202 = 0;
      puVar9 = &DAT_140034160;
      local_1fa = 0;
      puVar8 = (undefined8 *)&local_208;
      local_188 = 0;
      local_150 = 0;
      local_1c8 = 0;
      uStack_1c0 = 0;
      local_1b8 = FUN_140001e80;
      local_1b0 = FUN_140002310;
      local_1a8 = FUN_140002f90;
      local_1a0 = FUN_140002d20;
      local_170 = FUN_140002ab0;
      local_168 = FUN_140002c30;
      local_148 = FUN_140003510;
      local_198 = FUN_140003300;
      local_190 = FUN_140003460;
      local_160 = 0;
      uStack_158 = 0;
      local_180 = FUN_140002dc0;
      local_178 = FUN_140003080;
      *(code **)(param_1 + 0x68) = FUN_140003670;
      local_1f8 = local_138;
      uStack_1f0 = uStack_130;
      DAT_140034160 = (char *)0x0;
      local_204 = 6;
      local_1e8 = local_128;
      uStack_1e4 = uStack_124;
      uStack_1e0 = uStack_120;
      uStack_1dc = uStack_11c;
      local_1d8 = local_118;
      uStack_1d4 = uStack_114;
      uStack_1d0 = uStack_110;
      uStack_1cc = uStack_10c;
      uVar2 = NdisFRegisterFilterDriver(param_1,&DAT_140034150);
      uVar3 = (ulonglong)uVar2;
      if (uVar2 == 0) {
        RtlInitUnicodeString(local_108,L"\\Device\\VBoxNetLwf");
        RtlInitUnicodeString(local_f8);
        FUN_140020580((longlong *)local_e8,0,(undefined1 *)0xe0);
        local_e8[0] = FUN_1400023d0;
        puVar8 = &DAT_140034158;
        local_58 = FUN_1400023d0;
        puVar7 = &local_248;
        local_d8 = FUN_1400023d0;
        local_78 = FUN_1400023d0;
        puVar9 = &DAT_140034150;
        local_240 = local_108;
        local_248 = 0x380185;
        local_238 = local_f8;
        local_230 = local_e8;
        local_228 = 0;
        uStack_220 = 0;
        local_218 = 0;
        pcVar6 = DAT_140034160;
        uVar4 = NdisRegisterDeviceEx();
        uVar3 = uVar4 & 0xffffffff;
        if ((int)uVar4 == 0) {
          return uVar4;
        }
      }
      else {
        puVar7 = (undefined8 *)(ulonglong)uVar2;
        pcVar6 = "vboxNetLwfWinRegister: failed to register filter driver, status=0x%x";
        DbgPrint();
      }
      FUN_140002420(pcVar6,puVar7,(ulonglong)puVar8,puVar9);
      return uVar3;
    }
    RTR0Term(puVar5,param_2,param_3,param_4);
  }
  return 0xc0000001;
}

