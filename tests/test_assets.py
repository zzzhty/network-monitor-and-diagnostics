"""Network failure must not publish partial assets; architecture selects the package."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]


class AssetTests(unittest.TestCase):
    def test_download_failure_and_architecture_selection(self):
        for machine, package, fail in (("x86_64", "amd64", True), ("aarch64", "arm64", False)):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                shutil.copy2(SOURCE / "fetch-assets.sh", root / "fetch-assets.sh")
                bindir = root / "bin"
                bindir.mkdir()
                (bindir / "uname").write_text(f"#!/bin/sh\necho {machine}\n")
                (bindir / "uname").chmod(0o755)
                (bindir / "curl").write_text('''#!/usr/bin/python3
import os,sys
from pathlib import Path
args=sys.argv[1:]
dest=Path(args[args.index('-o')+1])
with open(os.environ['MH_TEST_URLS'],'a') as log: log.write(args[-1]+'\\n')
dest.write_text('downloaded')
if os.environ['MH_TEST_FAIL']=='1' and dest.name=='GeoSite.dat': sys.exit(22)
''')
                (bindir / "curl").chmod(0o755)
                names = ("mihomo.deb", "geoip.metadb", "GeoSite.dat")
                for name in names:
                    (root / name).write_text("previous usable asset")
                env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                           MH_TEST_URLS=str(root / "urls"), MH_TEST_FAIL=str(int(fail)))
                result = subprocess.run(["bash", str(root / "fetch-assets.sh")], env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 22 if fail else 0, result.stderr)
                self.assertIn(f"mihomo-linux-{package}-", (root / "urls").read_text())
                for name in names:
                    self.assertEqual((root / name).read_text(),
                                     "previous usable asset" if fail else "downloaded")
                self.assertFalse(list(root.glob(".assets.*")))


if __name__ == "__main__":
    unittest.main()
