"""Per-node persistent model service. Only the run-scoped SQLite wrapper changes."""
from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .dedicated_inference import DedicatedModel

TOKEN = re.compile(r"[0-9a-f]{64}\Z")
RUN = re.compile(r"[0-9a-f]{32}\Z")
NODE = re.compile(r"node-[0-9]+\Z")
MAX = 512 * 1024


class ResidentError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ResidentError("Resident HTTP redirect rejected")


def exchange(port, bearer, request, *, timeout):
    if type(port) is not int or not 0<port<65536 or not TOKEN.fullmatch(bearer):
        raise ValueError("Invalid private resident endpoint binding")
    req=Request(f"http://127.0.0.1:{port}/ipc",method="POST",
        headers={"Authorization":f"Bearer {bearer}","Content-Type":"application/json"},
        data=json.dumps(request,ensure_ascii=False).encode())
    try:
        with build_opener(ProxyHandler({}),_NoRedirect()).open(req,timeout=timeout) as reply:
            raw=reply.read(MAX+1)
    except HTTPError as e:
        status=e.code
        e.close()
        raise ResidentError(f"Private resident request refused (HTTP {status})") from None
    except (URLError,OSError):
        raise ResidentError("Private resident unavailable; generation status unknown") from None
    if len(raw)>MAX:
        raise ResidentError("Oversized reply from resident model")
    response=json.loads(raw)
    if not isinstance(response,dict):
        raise ResidentError("Invalid reply from resident model")
    return response


class ResidentClient:
    """Drop-in for only the methods the short-lived protocol process uses."""
    ENV=frozenset(("N20_RESIDENT_PORT","N20_RESIDENT_TOKEN","N20_RESIDENT_EPOCH","N20_RESIDENT_PID"))
    def __init__(self, env, node_id, *, timeout=600):
        if not self.ENV <= set(env):
            raise ResidentError("Missing resident endpoint binding; cold fallback is forbidden")
        self.port=int(env["N20_RESIDENT_PORT"])
        self.token=env["N20_RESIDENT_TOKEN"]
        self.epoch=env["N20_RESIDENT_EPOCH"]
        self.pid=int(env["N20_RESIDENT_PID"])
        self.run=env["MODEL_RUN_ID"]
        self.node=node_id
        self.quantization=env["MODEL_QUANTIZATION"]
        self.dtype=env["MODEL_DTYPE"]
        self.loaded=False
        self.timeout=timeout
        if not RUN.fullmatch(self.run) or not TOKEN.fullmatch(self.epoch):
            raise ResidentError("Invalid resident run/epoch")

    def _call(self, op, **data):
        result=exchange(self.port,self.token,dict(op=op,node=self.node,run=self.run,epoch=self.epoch,**data),
                        timeout=self.timeout if op=="generate" else 10)
        if (result.get("node"),result.get("run"),result.get("epoch"),result.get("pid")) != (
                self.node,self.run,self.epoch,self.pid):
            raise ResidentError("Private resident returned a different identity")
        return result

    def ensure_loaded(self):
        reply=self._call("health")
        if (reply.get("loaded") is not True or reply.get("quantization")!=self.quantization
                or reply.get("dtype")!=self.dtype):
            raise ResidentError("Resident model precision or readiness does not match")
        self.loaded=True

    def generate(self, **query):
        return self._generation_operation("generate", query)

    def read_generation(self, **query):
        return self._generation_operation("read_generation", query)

    def _generation_operation(self, op, query):
        reply=self._call(op,**query)
        if reply.get("round_index")!=query["round_index"] or reply.get("seed")!=query["seed"]:
            raise ResidentError("Private resident response does not match the request")
        return reply["result"]

    def record_response(self, round_index, answer, base_node):
        reply=self._call("record_response",round_index=round_index,answer=answer,base_node=base_node)
        if reply.get("round_index")!=round_index:
            raise ResidentError("Private resident did not bind the recorded response")


class Actor:
    def __init__(self, init, *, test_model=False):
        self.node=init["node"]
        self.admin=init["admin"]
        self.root=Path(init["root"]).resolve(strict=True)
        self.model_config=init["model_config"]
        if not NODE.fullmatch(self.node) or not TOKEN.fullmatch(self.admin) or not self.root.is_dir():
            raise ValueError("Invalid dedicated resident bootstrap")
        self.test_model=test_model
        self.model=None
        self.loads=0
        self.active=None
        self.calls=0
        self.by_run={}
        self.pid=__import__("os").getpid()

    def _load(self):
        if self.model is None:
            if self.test_model:
                # This isolated test hook cannot produce real BF16 runtime metadata.
                def sample(question,**kwargs):
                    self.calls+=1
                    by_round=self.by_run.setdefault(self.active["run"],{})
                    seed=kwargs["seed"]
                    by_round[str(seed)]=by_round.get(str(seed),0)+1
                    return 17,"#### 17"
                from types import SimpleNamespace
                self.model=SimpleNamespace(sample=sample)
            else:
                from .inference import ModelBackend
                c=self.model_config
                self.model=ModelBackend(c["model_name"],device=c["device"],dtype=c["dtype"],
                                        max_new_tokens=c["max_new_tokens"],quantization=None)
                if str(self.model.model.dtype)!="torch.bfloat16":
                    raise ValueError("Resident model did not actually load in BF16")
            self.loads+=1
        return self.model

    def _open(self, m):
        if self.active is not None:
            raise ValueError("Existing scenario must close before activation")
        rid,epoch,token,deadline=(m[k] for k in ("run","epoch","token","deadline"))
        if (not RUN.fullmatch(rid) or not TOKEN.fullmatch(epoch) or not TOKEN.fullmatch(token)
                or hmac.compare_digest(token,self.admin) or type(deadline) not in (int,float)
                or not time.time()<deadline<=time.time()+7200):
            raise ValueError("Invalid scoped case lease or deadline")
        work=self.root/rid
        cache=work/"node-models"/self.node
        if work.resolve(strict=True)!=work or not work.is_dir() or cache.resolve()!=cache:
            raise ValueError("Resident cache escapes the original durable run directory")
        db=cache/"inferencias.sqlite"
        if db.is_symlink() or db.is_file() is not m["resume"]:
            raise ValueError("Fresh and resumed caches must not be mixed")
        tasks=m["tasks"]
        if not isinstance(tasks,list) or not 1<=len(tasks)<=50:
            raise ValueError("Invalid exact per-node request set")
        if self.test_model:
            wrapper=DedicatedModel(node_id=self.node,run_id=rid,cache_dir=cache,
                                   factory=self._load,**self.model_config)
            wrapper.ensure_loaded()
        else:
            wrapper=DedicatedModel(node_id=self.node,run_id=rid,cache_dir=cache,
                                   resident_model=self._load(),**self.model_config)
            wrapper.ensure_loaded()
        self.active=dict(run=rid,epoch=epoch,token=token,deadline=deadline,tasks=tasks,backend=wrapper)

    def handle(self, auth, m):
        if not isinstance(m,dict) or m.get("node")!=self.node:
            raise ValueError("Wrong node identity")
        op=m.get("op")
        rid=m.get("run")
        if hmac.compare_digest("Bearer "+self.admin,auth):
            if op=="open":
                self._open(m)
            elif op=="close":
                if self.active is None or (rid,m.get("epoch"))!=(self.active["run"],self.active["epoch"]):
                    raise ValueError("Wrong scenario close")
                self.active=None
            elif op!="stats":
                raise ValueError("Unknown administrative operation")
            return {"node":self.node,"run":rid,"pid":self.pid,"epoch":m.get("epoch"),
                    "loads":self.loads,"mock":self.test_model,"calls":self.calls if self.test_model else None,
                    "by_run":self.by_run if self.test_model else None}
        a=self.active
        if (a is None or not hmac.compare_digest("Bearer "+a["token"],auth)
                or (rid,m.get("epoch"))!=(a["run"],a["epoch"])
                or time.time()>=a["deadline"]):
            raise PermissionError("Stale or unauthorized resident call")
        backend=a["backend"]
        result={"node":self.node,"run":rid,"pid":self.pid,"epoch":a["epoch"]}
        if op=="health":
            return {**result,"loaded":backend.loaded,"dtype":backend.dtype,"quantization":backend.quantization}
        r=m.get("round_index")
        if type(r) is not int or not 0<=r<len(a["tasks"]):
            raise ValueError("Round outside active schedule")
        if op in ("generate","read_generation"):
            expected=a["tasks"][r]
            if [m.get(k) for k in ("task_id","question","seed")]!=expected:
                raise ValueError("Request differs from assigned task or seed")
            action = backend.generate if op=="generate" else backend.read_generation
            raw=action(round_index=r,task_id=expected[0],question=expected[1],seed=expected[2])
            return {**result,"round_index":r,"seed":expected[2],"result":raw}
        if op=="record_response":
            if not NODE.fullmatch(m["base_node"]) and not (m["base_node"] == "" and m["answer"] is None):
                raise ValueError("Unknown response source")
            backend.record_response(r,m["answer"],m["base_node"])
            return {**result,"round_index":r}
        raise ValueError("Unknown resident operation")


def serve(*, test_model=False):
    # The admin capability enters only via the parent's inherited anonymous pipe.
    init=json.loads(sys.stdin.readline(MAX))
    actor=Actor(init,test_model=test_model)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def setup(self):
            super().setup()
            self.connection.settimeout(10)
        def do_POST(self):
            try:
                length=int(self.headers.get("Content-Length","0"))
                if self.path!="/ipc" or not 0<length<=MAX:
                    raise ValueError("Bad private route or body")
                m=json.loads(self.rfile.read(length))
                response=actor.handle(self.headers.get("Authorization",""),m)
                body=json.dumps(response).encode()
                status=200
            except PermissionError:
                status,body=403,b"{}"
            except (TypeError,KeyError,ValueError):
                status,body=409,b"{}"
            except Exception:
                status,body=503,b"{}"
            try:
                self.send_response(status)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass

    with HTTPServer(("127.0.0.1",0),Handler) as server:
        print(json.dumps({"node":actor.node,"pid":actor.pid,"port":server.server_port}),flush=True)
        # Keep application/model notices out of the bootstrap pipe.
        sys.stdout=sys.stderr
        server.serve_forever()


if __name__=="__main__":
    if sys.argv[1:] != []:
        raise SystemExit(2)
    serve()
