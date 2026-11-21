
"""Source bundle and synthetic R2 helper checks; never start Docker or contact R2."""
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

from . import r2_docker_pilot, r2_m80_pilot

ROOT = Path(__file__).resolve().parent
DOCKER = ROOT / "local-docker"


def load_packer():
    spec=importlib.util.spec_from_file_location("tcc_local_zip_builder",DOCKER/"prepare.py")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LocalPilotTests(unittest.TestCase):
    def make_run(self,tmp,kind):
        archive=tmp/"payload.zip"
        extracted=tmp/"code"
        output=tmp/"artifact"
        load_packer().prepare(archive,kind)
        with ZipFile(archive) as z:
            entries=set(z.namelist())
            wanted={"pilot.py","pilot-tasks.json","sistema/__init__.py","sistema/simulate.py"}
            self.assertTrue(wanted<=entries)
            self.assertTrue(all(n in wanted or (PurePosixPath(n).parent==PurePosixPath("sistema/core")
                                                and n.endswith(".py")) for n in entries))
            taskrows=json.loads(z.read("pilot-tasks.json"))
            self.assertTrue(all(set(r)=={"id","question","answer"} for r in taskrows))
            self.assertEqual(len(taskrows), 5 if kind=="base" else 50)
            z.extractall(extracted)
        with self.assertRaises(FileExistsError):
            load_packer().prepare(archive,kind)
        code=("from pathlib import Path; import pilot,sys; "
              f"pilot.{'OUTPUT' if kind=='base' else 'OUT'}=Path(sys.argv[1]); pilot.main()")
        child_env={k:v for k,v in os.environ.items() if k.upper() in {
            "SYSTEMROOT","WINDIR","SYSTEMDRIVE","PATH","TEMP","TMP","HOME","LANG","PYTHONUTF8"}}
        run=subprocess.run([sys.executable,"-B","-c",code,str(output)],cwd=extracted,
                           env=child_env, capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode,0,run.stderr)
        return output, json.loads((output/"receipt.json").read_text(encoding="utf-8"))

    def test_five_round_mock_and_synthetic_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            output, receipt=self.make_run(Path(temp),"base")
            self.assertEqual(receipt["verified_node_rounds"],100)
            self.assertFalse(receipt["live_llm"])
            data=r2_docker_pilot.archive_run(output)
            with ZipFile(io.BytesIO(data)) as z:
                self.assertEqual(set(z.namelist()),{"receipt.json","pilot/rounds.csv","pilot/per_node.csv"})
                self.assertIsNone(z.testzip())

    def test_fifty_round_m80_mock_and_download_consumer(self):
        with tempfile.TemporaryDirectory() as temp:
            output,receipt=self.make_run(Path(temp),"m80")
            self.assertEqual(receipt["verified_node_rounds"],1000)
            self.assertEqual(receipt["missing_malicious"],248)
            self.assertEqual(receipt["genesis_rounds"],[1,2,3])
            self.assertFalse(receipt["live_llm"])
            svg=output/"ema-eventos-final.svg"
            svg.write_text('<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0L1 1"/></svg>',encoding="utf-8")
            data=r2_m80_pilot.build_archive(output)
            consumed=r2_m80_pilot.consume_download(output,data)
            self.assertEqual(consumed["downloaded_rounds"],50)
            self.assertEqual(consumed["downloaded_node_rounds"],1000)
            self.assertEqual(consumed["downloaded_ema_checkpoints"],51)
            self.assertEqual((output/"r2-downloaded.zip").read_bytes(),data)
            svg.write_text('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>',encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"active"):
                r2_m80_pilot.build_archive(output)


if __name__=="__main__":
    unittest.main()
