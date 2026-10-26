
void FUN_18016c4b0(longlong param_1,byte param_2,short param_3,short param_4,byte param_5)

{
  ushort uVar1;
  undefined2 uVar2;
  ushort uVar3;
  
  param_1 = (ulonglong)param_2 + param_1;
  uVar3 = ((ushort)param_5 - (ushort)param_2) + param_3;
  uVar1 = (*(ushort *)(param_1 + 4) >> 8 | *(ushort *)(param_1 + 4) << 8) + param_4;
  *(ushort *)(param_1 + 4) = uVar1 >> 8 | uVar1 * 0x100;
  *(ushort *)(param_1 + 2) = uVar3 >> 8 | uVar3 * 0x100;
  uVar2 = RTNetIPv4HdrChecksum(param_1);
  *(undefined2 *)(param_1 + 10) = uVar2;
  RTNetIPv4PseudoChecksum(param_1);
  return;
}

