
int nocrt_memcmp(longlong *param_1,longlong *param_2,ulonglong param_3)

{
  longlong lVar1;
  longlong lVar2;
  ulonglong uVar3;
  longlong lVar4;
  longlong *plVar5;
  longlong *plVar6;
  longlong *plVar7;
  longlong *plVar8;
  longlong *plVar9;
  longlong *plVar10;
  bool bVar11;
  
                    /* 0x42650  1627  nocrt_memcmp */
  uVar3 = param_3 >> 3;
  bVar11 = true;
  do {
    plVar6 = param_2;
    plVar9 = param_1;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    plVar9 = param_1 + 1;
    plVar6 = param_2 + 1;
    bVar11 = *param_2 == *param_1;
    param_2 = plVar6;
    param_1 = plVar9;
  } while (bVar11);
  if (bVar11) {
    plVar7 = plVar6;
    plVar10 = plVar9;
    if ((param_3 & 4) != 0) {
      plVar10 = (longlong *)((longlong)plVar9 + 4);
      plVar7 = (longlong *)((longlong)plVar6 + 4);
      if ((int)*plVar6 != (int)*plVar9) {
        lVar4 = 4;
        do {
          plVar5 = plVar6;
          plVar8 = plVar9;
          if (lVar4 == 0) break;
          lVar4 = lVar4 + -1;
          lVar1 = *plVar9;
          lVar2 = *plVar6;
          plVar5 = (longlong *)((longlong)plVar6 + 1);
          plVar6 = (longlong *)((longlong)plVar6 + 1);
          plVar8 = (longlong *)((longlong)plVar9 + 1);
          plVar9 = (longlong *)((longlong)plVar9 + 1);
        } while ((char)lVar2 == (char)lVar1);
        goto LAB_18004269d;
      }
    }
    plVar6 = plVar7;
    plVar9 = plVar10;
    if ((param_3 & 2) != 0) {
      plVar9 = (longlong *)((longlong)plVar10 + 2);
      plVar6 = (longlong *)((longlong)plVar7 + 2);
      if ((short)*plVar7 != (short)*plVar10) {
        lVar4 = 2;
        do {
          plVar5 = plVar7;
          plVar8 = plVar10;
          if (lVar4 == 0) break;
          lVar4 = lVar4 + -1;
          plVar8 = (longlong *)((longlong)plVar10 + 1);
          plVar5 = (longlong *)((longlong)plVar7 + 1);
          lVar1 = *plVar10;
          lVar2 = *plVar7;
          plVar7 = plVar5;
          plVar10 = plVar8;
        } while ((char)lVar2 == (char)lVar1);
        goto LAB_18004269d;
      }
    }
    if ((param_3 & 1) == 0) {
      return 0;
    }
    plVar5 = (longlong *)((longlong)plVar6 + 1);
    plVar8 = (longlong *)((longlong)plVar9 + 1);
    if ((char)*plVar6 == (char)*plVar9) {
      return 0;
    }
  }
  else {
    lVar4 = 8;
    plVar6 = plVar6 + -1;
    plVar9 = plVar9 + -1;
    do {
      plVar5 = plVar6;
      plVar8 = plVar9;
      if (lVar4 == 0) break;
      lVar4 = lVar4 + -1;
      lVar1 = *plVar9;
      lVar2 = *plVar6;
      plVar5 = (longlong *)((longlong)plVar6 + 1);
      plVar6 = (longlong *)((longlong)plVar6 + 1);
      plVar8 = (longlong *)((longlong)plVar9 + 1);
      plVar9 = (longlong *)((longlong)plVar9 + 1);
    } while ((char)lVar2 == (char)lVar1);
  }
LAB_18004269d:
  return (uint)*(byte *)((longlong)plVar8 + -1) - (uint)*(byte *)((longlong)plVar5 + -1);
}

