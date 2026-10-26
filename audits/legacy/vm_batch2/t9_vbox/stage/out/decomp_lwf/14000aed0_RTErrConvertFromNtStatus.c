
undefined8 RTErrConvertFromNtStatus(int param_1)

{
  undefined8 ****ppppuVar1;
  
                    /* 0xaed0  29  RTErrConvertFromNtStatus */
  if (param_1 < -0x3ffffffc) {
    if (param_1 == -0x3ffffffd) {
      return 0xffffffdc;
    }
    if (param_1 == -0x7ffffffe) {
switchD_14000af56_caseD_c0000005:
      return 0xfffffffa;
    }
    if ((param_1 == -0x7ffffffa) || (param_1 == -0x7fffffe6)) {
      return 0xffffff37;
    }
  }
  else if (param_1 < -0x3ffffe6f) {
    if (param_1 == -0x3ffffe70) {
      return 0xfffff141;
    }
    switch(param_1) {
    case -0x3ffffffb:
      goto switchD_14000af56_caseD_c0000005;
    case -0x3ffffff8:
      return 0xfffffffc;
    case -0x3ffffff3:
    case -0x3fffff11:
    case -0x3fffff10:
    case -0x3fffff0f:
    case -0x3fffff0e:
    case -0x3fffff0d:
    case -0x3fffff0c:
    case -0x3fffff0b:
    case -0x3fffff0a:
    case -0x3fffff09:
    case -0x3fffff08:
    case -0x3fffff07:
    case -0x3fffff06:
      return 0xfffffffe;
    case -0x3ffffff2:
    case -0x3ffffff1:
    case -0x3fffffcc:
      return 0xffffff9a;
    case -0x3ffffff0:
      return 0xffffff03;
    case -0x3fffffed:
      return 0xffffff5b;
    case -0x3fffffe9:
      return 0xfffffff8;
    case -0x3fffffde:
      return 0xffffffda;
    case -0x3fffffdc:
      return 0xffffff73;
    case -0x3fffffcd:
    case -0x3fffffc7:
    case -0x3fffffc5:
      return 0xffffff98;
    case -0x3fffffc6:
      return 0xffffff99;
    case -0x3fffffbd:
      return 0xffffff8e;
    case -0x3fffff93:
      return 0xffffffa7;
    case -0x3fffff46:
      return 0xffffff81;
    case -0x3fffff42:
      return 0xfffffe6d;
    case -0x3fffff3c:
      return 0xfffffe70;
    case -0x3ffffeff:
      return 0xffffff83;
    case -0x3ffffefd:
      return 0xffffff82;
    }
  }
  else {
    if (param_1 == -0x3ffffd80) {
      return 0xffffff64;
    }
    if (param_1 == -0x3ffffbd8) {
      return 0xfffffd95;
    }
    if (param_1 == 0) {
      return 0;
    }
    if ((param_1 == 0xc0) || (param_1 == 0x101)) {
      return 0xffffffd9;
    }
  }
  ppppuVar1 = (undefined8 ****)RTLogRelGetDefaultInstanceEx(0x10);
  if (ppppuVar1 != (undefined8 ****)0x0) {
    RTLogLoggerEx(ppppuVar1,0x10,0,"AssertLogRel %s(%d) %s: %s\n");
  }
  ppppuVar1 = (undefined8 ****)RTLogRelGetDefaultInstanceEx(0x10);
  if (ppppuVar1 != (undefined8 ****)0x0) {
    RTLogLoggerEx(ppppuVar1,0x10,0,"Unhandled error %#lx (%lu)\n");
  }
  return 0xffffffdd;
}

