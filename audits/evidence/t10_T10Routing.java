import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class T10Routing extends GhidraScript {
    PrintWriter w;
    DecompInterface di;
    ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

    void dumpFn(Function f) {
        if (f == null) { w.println("//---- <null function>"); return; }
        long trueRva = f.getEntryPoint().getOffset() - currentProgram.getImageBase().getOffset();
        w.println("//==== FN " + f.getName() + " @ " + f.getEntryPoint() + " (trueRVA=0x" + java.lang.Long.toHexString(trueRva) + ") ====");
        try {
            DecompileResults r = di.decompileFunction(f, 120, mon);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                w.println(r.getDecompiledFunction().getC());
            } else {
                w.println("DECOMP_FAILED");
            }
        } catch (Exception e) { w.println("EXC " + e); }
        w.println();
    }

    void dumpFnLabel(String label, long labelAddr) {
        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(labelAddr);
        Function f = getFunctionAt(a);
        if (f == null) f = getFunctionContaining(a);
        if (f == null) {
            w.println("//---- label 0x" + java.lang.Long.toHexString(labelAddr) + ": NO FUNCTION (unknown/un-analyzed)");
            return;
        }
        w.println("LABEL 0x" + java.lang.Long.toHexString(labelAddr) + " -> " + f.getName() + " @ " + f.getEntryPoint() + " (trueRVA=0x" + java.lang.Long.toHexString(f.getEntryPoint().getOffset() - currentProgram.getImageBase().getOffset()) + ")");
        dumpFn(f);
    }

    List<Function> referrerFns(Address tgt) {
        List<Function> out = new ArrayList<Function>();
        ReferenceIterator rit = currentProgram.getReferenceManager().getReferencesTo(tgt);
        while (rit.hasNext()) {
            Reference rf = rit.next();
            Address src = rf.getFromAddress();
            Function f = getFunctionContaining(src);
            String fn = (f == null) ? "?" : (f.getName() + "@" + f.getEntryPoint());
            w.println("REF src=" + src + " type=" + rf.getReferenceType() + " fn=" + fn);
            if (f != null) out.add(f);
        }
        return out;
    }

    List<Function> nameRefFns(String nm) {
        List<Function> out = new ArrayList<Function>();
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator sit = st.getAllSymbols(true);
        boolean found = false;
        while (sit.hasNext()) {
            Symbol s = sit.next();
            if (s.getName().equals(nm)) {
                found = true;
                w.println("SYM " + nm + " @ " + s.getAddress() + " ns=" + s.getParentNamespace().getName());
                out.addAll(referrerFns(s.getAddress()));
            }
        }
        if (!found) w.println("SYM " + nm + " NOT FOUND");
        return out;
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args[0];
        new File(outDir).mkdirs();
        w = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "t10_static_assist.txt")), 1 << 20));
        di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(currentProgram);

        w.println("IMAGE BASE " + currentProgram.getImageBase());
        w.println("NOTE: audit/reports use label-space addresses (no base add). trueFileRVA = label - imageBase.");
        w.println();

        // 1) entry points / DriverEntry
        AddressIterator ai = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        Function entry = null;
        while (ai.hasNext()) {
            Address a = ai.next();
            Function f = getFunctionAt(a);
            if (f == null) f = getFunctionContaining(a);
            w.println("ENTRY PT " + a + " -> " + (f == null ? "?" : f.getName()));
            if (entry == null && f != null) entry = f;
        }
        if (entry != null) dumpFn(entry); else w.println("NO ENTRY FUNCTION FOUND");
        w.println();

        // 2) refs to the IOCTL dispatch (label 0x5c084)
        long baseOff = currentProgram.getImageBase().getOffset();
        w.println("##REFS dispatch label 0x5c084");
        List<Function> l1 = referrerFns(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x5c084L));
        w.println();
        dumpFnLabel("dispatch", 0x5c084L);
        for (Function f : l1) dumpFn(f);
        w.println();

        // 3) refs to defect handlers / gate / device-creation functions (label-space)
        long[] labels = {0x5dcf0L, 0x5e300L, 0x5f908L, 0x582a8L, 0x11a008L};
        for (long r : labels) {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(r);
            w.println("##REFS fn label 0x" + java.lang.Long.toHexString(r) + " (trueRVA=0x" + java.lang.Long.toHexString(r - baseOff) + ")");
            List<Function> ls = referrerFns(a);
            w.println();
            dumpFnLabel("t", r);
            for (Function f : ls) dumpFn(f);
        }

        // 4) import call sites
        String[] imps = {"IoCreateDevice", "IoCreateSymbolicLink", "IoRegisterDeviceInterface",
                         "IoCreateDeviceSecure", "IoCreateFile", "IoDeleteDevice"};
        for (String nm : imps) {
            w.println("##IMPORT " + nm);
            List<Function> ls = nameRefFns(nm);
            w.println();
            for (Function f : ls) dumpFn(f);
        }

        w.println("##DONE");
        w.close();
        println("T10 ROUTING DONE");
    }
}
