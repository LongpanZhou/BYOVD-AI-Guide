
void RTLogRelGetDefaultInstanceEx(undefined4 param_1)

{
  ulonglong uVar1;
  longlong lVar2;
  
                    /* 0x80830  463  RTLogRelGetDefaultInstanceEx */
  lVar2 = GVMMR0GetGVCpuByEMT(0xffffffffffffffff);
  if ((((lVar2 != 0) && (uVar1 = *(ulonglong *)(lVar2 + 0x3c808), 0x1fff < uVar1 + 0x1000)) &&
      (((uVar1 & 0xffff800000000000) + 0x800000000000 & 0xffff7fffffffffff) == 0)) &&
     (((*(longlong *)(uVar1 + 8) == lVar2 && (*(longlong *)(uVar1 + 0x10) == lVar2)) &&
      (*(char *)(lVar2 + 0x3c892) == '\0')))) {
    RTLogCheckGroupFlags(uVar1,param_1);
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x0001800808b4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  SUPR0GetDefaultLogRelInstanceEx(param_1);
  return;
}

