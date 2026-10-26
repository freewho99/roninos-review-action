import os
import sys
from pathlib import Path

dest = Path(os.environ["RONINOS_DEST"]).resolve()
target = dest / "node_modules" / "roninos" / "bin" / "roninos.mjs"
if not target.is_file():
    raise SystemExit("RoninOS CLI bootstrap: installed CLI not found")

source = target.read_text(encoding="utf-8")
if "repositoryCanonicalSources" in source:
    sys.exit(0)

old = """  const tricorder = tricorderMod?.TricorderArchitecturalEngine
    ? new tricorderMod.TricorderArchitecturalEngine()
    : null;"""
new = """  const repositoryCanonicalSources = (tricorderMod?.CANONICAL_SHARED_UTILITIES || [])
    .map((util) => {
      const repoRoot = path.resolve(process.cwd());
      const fullPath = path.resolve(repoRoot, util.filePath);
      if (!fullPath.startsWith(repoRoot + path.sep)) return null;
      if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) return null;
      return { filePath: util.filePath, sourceCode: fs.readFileSync(fullPath, 'utf8') };
    })
    .filter(Boolean);
  const tricorder = tricorderMod?.TricorderArchitecturalEngine
    ? new tricorderMod.TricorderArchitecturalEngine({ repositorySources: repositoryCanonicalSources })
    : null;"""

if old not in source:
    raise SystemExit("RoninOS CLI bootstrap: expected tricorder construction not found")

target.write_text(source.replace(old, new), encoding="utf-8")
