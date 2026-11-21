"""Tiny, synchronized CUDA BF16 verification; no weights or provider operations."""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess


def driver_version():
    for path in (Path("/usr/bin/nvidia-smi"),Path("/usr/local/nvidia/bin/nvidia-smi")):
        if path.is_file():
            p=subprocess.run([str(path),"--query-gpu=driver_version","--format=csv,noheader,nounits"],
               check=True,timeout=5,stdin=subprocess.DEVNULL,capture_output=True,text=True,
               env={"PATH":"/usr/bin:/bin","LANG":"C"})
            versions=set(p.stdout.strip().splitlines())
            if len(versions)==1:
                val=next(iter(versions)).strip()
                if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}",val):
                    return val
            break
    raise RuntimeError("NVIDIA driver version not independently readable")


def verify(torch, count, *, read_driver=driver_version):
    if type(count) is not int or count<1 or not torch.cuda.is_available() or torch.cuda.device_count()!=count:
        raise RuntimeError("Expected exact count of dedicated CUDA devices")
    build=getattr(torch.version,"cuda",None)
    if not isinstance(build,str) or not build:
        raise RuntimeError("This Torch wheel has no CUDA build")
    record={"nvidia_driver":read_driver(),"torch_version":str(torch.__version__),"torch_cuda_build":build,
            "compiled_arches":list(torch.cuda.get_arch_list()),"device_results":[]}
    with torch.inference_mode():
        for i in range(count):
            try:
                with torch.cuda.device(i):
                    name=torch.cuda.get_device_name(i)
                    cc=list(torch.cuda.get_device_capability(i))
                    if torch.cuda.is_bf16_supported(including_emulation=False) is not True:
                        raise RuntimeError("Native BF16 unavailable")
                    # Allocate on the exact GPU; exercise elementwise and GEMM
                    # paths. 2x2 * inputs are exactly representable in BF16.
                    source=torch.full((2,2),2,device=f"cuda:{i}",dtype=torch.bfloat16)
                    plus=source+source
                    result=plus @ source
                    torch.cuda.synchronize(i)
                    if any(t.dtype!=torch.bfloat16 or t.get_device()!=i for t in (source,plus,result)):
                        raise RuntimeError("BF16 or device changed")
                    if plus.cpu().tolist()!=[[4,4],[4,4]] or result.cpu().tolist()!=[[16,16],[16,16]]:
                        raise RuntimeError("Unexpected BF16 arithmetic result")
                record["device_results"].append({"index":i,"name":name,"compute_capability":cc,"bf16_probe":"passed"})
            except Exception as exc:
                # No runtime fallback. Architecture list alone is not used as
                # a deny-list because a compatible PTX path may work.
                raise RuntimeError(f"CUDA BF16 kernel verification failed on device {i} "
                    f"(Torch {record['torch_version']}, CUDA {build}, driver {record['nvidia_driver']})") from exc
    return record


def main():
    import argparse
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--devices",type=int,choices=(1,2),default=2)
    args=cli.parse_args()
    import torch
    print(json.dumps(verify(torch,args.devices),sort_keys=True),flush=True)


if __name__=="__main__":
    main()
