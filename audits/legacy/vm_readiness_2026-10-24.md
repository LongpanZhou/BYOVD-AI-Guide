# VM readiness check: Windows 10 x64 (phase 0)

> **HISTORICAL one-off.** Current VM rules are in `../../VM_ACCESS.md`; current audit status is
> `../STATUS.md`. Do not treat the blocker state below as current.

Last updated 2026-10-24, about 06:46 host time. Host-side checks only. No guest command, file copy, start, stop, suspend, revert, snapshot, install, or device open was run. No guest credential is recorded in this file.

## 1. Summary

**STOPPED (BLOCKED)**

- Blocker 1: opencode is still running. opencode.exe PIDs 21540 and 23656 were both live at 06:45:55. Under the shared-use stop rule, no guest work was done. Nothing was killed.
- Blocker 2: consent. The coordinator's second message said the user confirmed directly that opencode is stopped and that full VM access is granted. A message from an agent cannot serve as the user's consent for guest execution, driver install, or a kernel write test. Step 7 of this phase still forbids run-in-guest. Direct confirmation from the user is needed.
- Not run: the guest checks (ver, whoami /groups, sc query b06bdrv and amdpsp, pnputil filter, Get-PnpDevice list); snapshot pre-b06bdrv-test; driver copy and install; the IOCTL 0x8000203C test; revert.
- Provisional device results (guest check still pending):
  - amdpsp: not reproducible: hardware missing. Basis: the earlier t8 guest run found no PSP device, and the VM has no PCI passthrough (section 2).
  - b06bdrv (bxvbda.sys): not reproducible: hardware missing. Provisional. Basis: no PCI passthrough, so no physical QLogic adapter is attached. The guest Get-PnpDevice check is still needed to confirm.
- Snapshot: only pre-driver-tests exists. No new snapshot was taken and nothing was reverted.
- Not blockers: VMware Tools reports running.

## 2. Host and VM facts

- vmrun.exe: `C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe` (found at the first path tried).
- `vmrun list`:
  ```
  Total running VMs: 1
  C:\Users\<scrubbed>\Downloads\Vmware\Windows 10 x64.vmx
  ```
- `vmrun listSnapshots "C:\Users\<scrubbed>\Downloads\Vmware\Windows 10 x64.vmx"`:
  ```
  Total snapshots: 1
  pre-driver-tests
  ```
  vmrun prints names only. No snapshot ID is shown.
- `vmrun checkToolsState` (same .vmx): `running`
- Host VM process: vmware-vmx.exe, PID 10620, started 2026-10-24 06:32:58 (parent vmware-authd.exe, PID 5144). This is a recent start. It does not show who started the VM.
- Virtual hardware from the .vmx (device lines only):
  ```
  sound.present = "TRUE"
  sata0.present = "TRUE"
  nvme0.present = "TRUE"
  usb.present = "TRUE"
  ethernet0.connectionType = "nat"
  ethernet0.virtualDev = "e1000e"
  ethernet0.present = "TRUE"
  ```
  No pciPassthru entries. The guest has a virtual Intel e1000e NIC. USB is present, but a QLogic NIC or an AMD PSP is not a USB device.

## 3. opencode activity

- Rechecked 06:45:55: opencode.exe PID 21540 (started 2026-10-23 15:21:06) and PID 23656 (started 2026-10-23 14:16:17) are both running. Both run from `C:\Users\<scrubbed>\AppData\Roaming\npm\node_modules\@opencode\cli\bin\opencode.exe`.
- At 06:39, PID 23656 had spawned pairs of python.exe and node.exe (`rea.mjs`) at 05:49:38, 05:54:39, 06:03:39, 06:10:39 and 06:19:40. All were still running at 06:39. In a 3-second sample at 06:39, PID 23656 used 0.27 CPU-seconds.
- No process command line mentions the .vmx path, vmrun, or driver_candidates.
- Lock or coordination files (names only): none found. The newest write under driver_candidates is README_VM.txt, 2026-10-24 04:53:53. An older opencode.db (2026-10-23 14:26:36) is in another session's scratchpad. In this session's tasks folder, three output files were written between 06:31 and 06:37 (a5a81d980c8f02f0e.output, a501c1fe3962e7368.output, bn975ch4t.output). Their owner is not established.
- Assessment: active. Both processes are live, and the parent was using CPU at the 06:39 check.
- Nothing was killed or changed.

## 4. Blockers

1. opencode still running (06:45:55). This clears only when the user stops it, or confirms it is idle and accepts the shared-use risk. I did not kill it.
2. Direct consent from the user. The relayed "user confirmed" message is not treated as consent for guest execution (step 7), for copying and installing a kernel driver, or for the IOCTL test. The user should confirm in their own message.
3. Guest checks not run. To run once the blockers above clear:
   - `ver`
   - `whoami /groups` (is the account an administrator?)
   - `sc query b06bdrv` and `sc query amdpsp`
   - `pnputil /enum-drivers`, filtered to qlogic, bcm, amd, intel and vbox
   - a `Get-PnpDevice` list of network, storage and PSP devices
4. Guest state unverified. Earlier runs left residue (section 6), so the guest should not be assumed clean.

## 5. Planned next phase (not executed)

Neither candidate is confirmed to work in this guest. amdpsp.sys is confirmed blocked. bxvbda.sys is unconfirmed.

The coordinator's conditional path: the validation runs only if a matching device is present in the guest. If not, report "not reproducible: hardware missing" and stop.

**Candidate 1: b06bdrv (bxvbda.sys, QLogic 10 GbE client driver), IOCTL 0x8000203C**
- Status: not run. Provisional result: not reproducible: hardware missing.
- Basis: `audits/b06bdrv_detailed.md` (V20). The audit describes an unchecked kernel write, with only count and alignment checks.
- If the guest check finds the device: take snapshot pre-b06bdrv-test. Copy bxvbda.sys to C:\validation in the guest and install it with pnputil. Confirm, without sending any IOCTL, whether the device interface exists and whether the guest account can open it. Send exactly one IOCTL 0x8000203C with count 1, a known data dword, and an unmapped canonical kernel destination that the operator chooses and records. The expected result is a bugcheck whose fault address equals that destination. Record the bugcheck code and fault address. Revert to pre-b06bdrv-test.
- Hardware dependency: the audit found no device name or SDDL of its own, and it leaves reachability open (O1). It describes BAR mapping through MmMapIoSpaceEx, which suggests a QLogic adapter is needed for a working interface. The guest check must settle this. The VM has no PCI passthrough, so no physical QLogic adapter is attached (section 2).
- Can it load without hardware: unknown until the guest check.

**Candidate 2: amdpsp.sys, IOCTL 0x9C422834**
- Status: not run. Result: not reproducible: hardware missing (per the prior guest evidence and section 2).
- Basis: `audits/amdpsp_detailed.md` (F19) and `audits/amdpsp.dynamic.md` (t8, same VM).
- Hardware dependency: confirmed. The driver starts as a service, but `\Device\amdpsp` is created only when an AMD PSP device arrives (ACPI\AMDPSP or PCI VEN_1022 PSP). This guest has neither. In the earlier t8 run, creating a device node failed: ROOT gave STATUS_NOT_SUPPORTED, and manual ACPI and PCI nodes were refused (CR_INVALID_DEVNODE). The IOCTL surface never existed in the guest, so the IOCTL was never sent.
- Can it load without hardware: it loads, but gives no IOCTL device, so it cannot be tested here.

## 6. Guardrails for the next phase

- Before the first test, revert to pre-driver-tests and confirm it is clean. Earlier runs left residue (for example, a delete-pending service and locked files, per `audits/amdpsp.dynamic.md`).
- One snapshot before each test, reverted after it. For the b06bdrv test, the snapshot is pre-b06bdrv-test.
- Dedicated guest folder: C:\validation.
- One IOCTL per test.
- No privilege escalation, no payload, no network access from the guest, and no artifacts copied off the guest.
- Do not run the PoC binaries left in earlier stage folders (t8_poc.exe, t9_poc.exe).
- If anything hangs, stop and report. Stop at once if opencode or any other tool shows activity in the VM.

## 7. Update log

- 06:39: The coordinator relayed a guest login and asked for read-only guest checks. Not run: opencode was active, and step 7 forbids run-in-guest. The login was not used or recorded.
- 06:45: The coordinator relayed a claim of direct user confirmation (opencode stopped, full VM access) and a conditional validation path. I checked opencode first: PIDs 21540 and 23656 were still running, so I stopped. I read the .vmx device lines on the host only. Not run: guest checks, snapshot, driver copy or install, IOCTL, revert. The relayed claim is not user consent.
