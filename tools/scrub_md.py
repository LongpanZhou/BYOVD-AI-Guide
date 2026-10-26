import os
root = os.environ["USERPROFILE"] + "\\Desktop\\driver_candidates"
pats = [b"Users\\27175", b"Users/27175", b"Users-27175"]
reps = [b"Users\\<scrubbed>", b"Users/<scrubbed>", b"Users-<scrubbed>"]
changed = 0
for dirpath, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in (".git",)]
    for f in files:
        if not f.lower().endswith(".md"):
            continue
        p = os.path.join(dirpath, f)
        if p.lower().endswith("vm_access.md"):
            continue
        b = open(p, "rb").read()
        nb = b
        for a, c in zip(pats, reps):
            nb = nb.replace(a, c)
        if nb != b:
            open(p, "wb").write(nb)
            changed += 1
print("md files scrubbed:", changed)
le = []
for dirpath, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in (".git",)]
    for f in files:
        if not f.lower().endswith(".md"): continue
        p = os.path.join(dirpath, f)
        if p.lower().endswith("vm_access.md"): continue
        data = open(p, "rb").read()
        if b"27175" in data:
            le.append(os.path.relpath(p, root))
print("leftover files:", len(le))
for x in le[:15]: print("  ", x)
