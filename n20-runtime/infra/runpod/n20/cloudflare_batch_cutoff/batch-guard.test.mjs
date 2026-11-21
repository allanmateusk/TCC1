import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { armState, armTime, claimState, pin, provider, runCutoffWorkflow, stopExact, terminalBytes, verifyTerminal } from "./src/batch-guard.mjs";

const ms=Date.parse("2026-11-21T18:00:00.000Z");
const at=x=>new Date(ms+x).toISOString();
const raw={batch:"f721260c-fedf-4fda-ad01-5544d2c49de2",owner:"test-owner",pod:"test-pod",
  datacenter:"TEST-1",name:"Known test Pod",startedAt:at(0),stopAt:at(17_700_000),deadline:at(18_000_000),
  gitSha:"2".repeat(40),profileSha256:"3".repeat(64),terminalPubKey:null};
const plan=pin(raw,raw,raw.batch);
class Storage {
  map=new Map();
  queue=Promise.resolve();
  transaction(fn) {
    const call=this.queue.then(()=>fn({get:async key=>this.map.get(key), put:async (key,v)=>this.map.set(key,v)}));
    this.queue=call.catch(()=>{});
    return call;
  }
}
function standin({override={},owner=raw.owner,postMode="exit"}={}) {
  let state="RUNNING";
  let calls=[];
  return {calls, request:async (url,method)=>{
    calls.push([url,method]);
    if (url.endsWith("/account")) return {status:200,data:{id:owner}};
    if (method==="POST") {
      if (postMode!=="stuck") state="EXITED";
      if (postMode==="lost") throw Error("Mock lost ACK");
      return {status:202};
    }
    return {status:200,data:{id:raw.pod,name:raw.name,dataCenterId:raw.datacenter,
                            cloud:"SECURE",status:state,actions:["stop"],...override}};
  }};
}
const opts=(p,f,s,kind,t)=>({request:f.request,claim:()=>claimState(s,p,kind,t),now:()=>t,pause:async()=>{}});
const writes=f=>f.calls.filter(x=>x[1]==="POST").length;

test("default source is disarmed; config has no HTTP, previews, cron or legacy route",async()=>{
  const config=JSON.parse(await readFile(new URL("./wrangler.jsonc",import.meta.url),"utf8"));
  const source=await readFile(new URL("./src/index.mjs",import.meta.url),"utf8");
  assert.match(source,/const APPROVED=null;/);
  assert.match(source,/runCutoffWorkflow\(plan,step/);
  assert.equal(config.workers_dev,false);
  assert.equal(config.preview_urls,false);
  assert.deepEqual(config.routes,[]);
  assert.equal(config.triggers,undefined);
  assert.equal(config.durable_objects.bindings.length,1);
});
test("exact scope and 4–7h, UTC, wake margin, startup bounds are enforced",()=>{
  for (const changes of [{owner:"other-owner"},{profileSha256:"f".repeat(64)},{untrusted:true}])
    assert.throws(()=>pin(raw,{...raw,...changes},raw.batch),/DISARMED_OR_WRONG_BATCH/);
  assert.throws(()=>pin(null,raw,raw.batch),/DISARMED/);
  assert.throws(()=>pin(raw,raw,"unrelated"),/DISARMED/);
  const over={...raw,stopAt:at(8*3600000-300000),deadline:at(8*3600000)};
  assert.throws(()=>pin(over,over,over.batch),/WINDOW/);
  const tooSoon={...raw,stopAt:at(3*3600000-300000),deadline:at(3*3600000)};
  assert.throws(()=>pin(tooSoon,tooSoon,tooSoon.batch),/WINDOW/);
  const bad={...raw,stopAt:raw.deadline};
  assert.throws(()=>pin(bad,bad,bad.batch),/WINDOW/);
  assert.throws(()=>armTime(plan,ms+300001),/FIVE/);
  assert.throws(()=>armTime(plan,ms-1),/FIVE/);
  assert.doesNotThrow(()=>armTime(plan,ms+300000));
});
test("same owner plus Pod cannot be silently rebased to a different batch or pinned code",async()=>{
  const storage=new Storage();
  assert.equal(await armState(storage,plan),true);
  assert.equal(await armState(storage,plan),true);
  const different={...raw,batch:"82e2415e-840a-4aac-b77e-712bd08670ca"};
  assert.equal(await armState(storage,pin(different,different,different.batch)),false);
  assert.equal(await claimState(storage,pin(different,different,different.batch),"cutoff",plan.wake),false);
});
test("terminal and deadline can race; shared durable claim allows one STOP total",async()=>{
  const storage=new Storage(), f=standin();
  assert.equal(await claimState(storage,plan,"terminal",plan.wake),false);
  await armState(storage,plan);
  const [a,b]=await Promise.all(["terminal","cutoff"].map(kind=>stopExact(plan,kind,opts(plan,f,storage,kind,plan.wake))));
  assert.equal(writes(f),1);
  assert.equal(a.state,"STOP_CONFIRMED"); assert.equal(b.state,"STOP_CONFIRMED");
  const again=await stopExact(plan,"cutoff",opts(plan,f,storage,"cutoff",plan.wake+1000));
  assert.equal(again.state,"STOP_CONFIRMED"); assert.equal(writes(f),1);
});
test("lost claim can only reconcile, and lost POST gets an independent EXITED read",async()=>{
  const storage=new Storage(), f=standin({postMode:"lost"}), g=standin();
  await armState(storage,plan);
  const lostClaim={...opts(plan,g,storage,"cutoff",plan.wake),claim:async()=>{
    await claimState(storage,plan,"cutoff",plan.wake);
    throw Error("Lost claim ACK");
  }};
  assert.equal((await stopExact(plan,"cutoff",lostClaim)).reason,"CLAIM_NOT_GRANTED_GET_ONLY");
  assert.equal(writes(g),0);
  const other=new Storage();
  await armState(other,plan);
  assert.equal((await stopExact(plan,"cutoff",opts(plan,f,other,"cutoff",plan.wake))).state,"STOP_CONFIRMED");
  assert.equal(writes(f),1); assert.equal(f.calls.at(-1)[1],"GET");
});
test("202 with RUNNING still is not a verified stop; cannot POST twice",async()=>{
  const storage=new Storage(), f=standin({postMode:"stuck"});
  await armState(storage,plan);
  assert.equal((await stopExact(plan,"cutoff",opts(plan,f,storage,"cutoff",plan.wake))).reason,"STOP_NOT_CONFIRMED");
  assert.equal((await stopExact(plan,"cutoff",opts(plan,f,storage,"cutoff",plan.wake))).reason,"CLAIM_NOT_GRANTED_GET_ONLY");
  assert.equal(writes(f),1);
});
test("wrong owner, Pod, datacenter or cloud; early wake and missed window are nonmutating",async()=>{
  const storage=new Storage();
  await armState(storage,plan);
  for (const f of [standin({owner:"other"}),standin({override:{id:"other"}}),
      standin({override:{dataCenterId:"other"}}),standin({override:{cloud:"COMMUNITY"}})]) {
    assert.equal((await stopExact(plan,"cutoff",opts(plan,f,storage,"cutoff",plan.wake))).state,"MANUAL_REQUIRED");
    assert.equal(writes(f),0);
  }
  const f=standin();
  assert.equal((await stopExact(plan,"cutoff",opts(plan,f,storage,"cutoff",plan.wake-1))).reason,"EARLY_WAKE");
  assert.equal((await stopExact(plan,"cutoff",opts(plan,f,storage,"cutoff",plan.end))).reason,"DEADLINE_PASSED");
  assert.equal(writes(f),0);
});
test("already EXITED is affirmative GET proof without issuing a STOP",async()=>{
  const f=standin({override:{status:"EXITED"}});
  assert.equal((await stopExact(plan,"cutoff",opts(plan,f,new Storage(),"cutoff",plan.end+1))).reason,"EXITED_LATE");
  assert.equal(writes(f),0);
});
test("terminal needs fresh independent Ed25519 proof for exact 20 receipts",async()=>{
  const pair=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
  const pk=Buffer.from(await crypto.subtle.exportKey("raw",pair.publicKey)).toString("base64url");
  const armed={...raw,terminalPubKey:pk};
  const q=pin(armed,armed,armed.batch);
  const now=plan.start+600000;
  const record={schema:"tcc-batch-early-stop/v1",batch:q.batch,pod:q.pod,owner:q.owner,gitSha:q.gitSha,
    profileSha256:q.profileSha256,verifiedCases:20,receiptSetSha256:"d".repeat(64),observedAt:new Date(now-1000).toISOString()};
  const proof=Buffer.from(await crypto.subtle.sign("Ed25519",pair.privateKey,terminalBytes(record))).toString("base64url");
  await verifyTerminal(q,record,proof,now);
  await assert.rejects(verifyTerminal(plan,record,proof,now),/INVALID/);
  await assert.rejects(verifyTerminal(q,{...record,verifiedCases:19},proof,now),/INVALID/);
  await assert.rejects(verifyTerminal(q,{...record,receiptSetSha256:"e".repeat(64)},proof,now),/INVALID/);
  await assert.rejects(verifyTerminal(q,record,proof,now+60000),/STALE/);
});
test("transport permits only exact official shape and forbids redirect and delete",async()=>{
  const calls=[];
  const mock=provider(async (url,opts)=>{
    calls.push([url,opts]);
    return {status:202,body:{cancel:async()=>{}}};
  },"fixture-not-a-secret");
  await assert.rejects(mock("https://other.example/v2/pods/test-pod/action","POST"),/UNEXPECTED/);
  await assert.rejects(mock("https://api.runpod.io/v2/pods/test-pod","DELETE"),/UNEXPECTED/);
  await mock("https://api.runpod.io/v2/pods/test-pod/action","POST");
  assert.equal(calls.length,1);
  assert.equal(calls[0][1].redirect,"error");
  assert.deepEqual(JSON.parse(calls[0][1].body),{action:"stop"});
});


test("workflow helper persists exact approval before sleeping at absolute UTC, then runs bounded stop",async()=>{
  let t=plan.start+1000;
  const order=[];
  const worker={do:async(name,config,fn)=>{
    order.push(name); assert.equal(config.retries.limit,0); return fn();
  }, sleepUntil:async(name,time)=>{
    order.push(name); assert.equal(time.toISOString(),raw.stopAt); t=time.getTime();
  }};
  assert.equal(await runCutoffWorkflow(plan,worker,{now:()=>t,arm:async()=>true,perform:async()=>{
    assert.equal(t,plan.wake); return "done";
  }}),"done");
  assert.deepEqual(order,["bind-exact-batch","absolute-batch-cutoff","cutoff-stop-or-reconcile"]);
});
test("workflow refuses missing/reused claim before reaching sleep or provider",async()=>{
  const worker={do:async(_name,_cfg,fn)=>fn(), sleepUntil:()=>assert.fail("must not sleep")};
  await assert.rejects(runCutoffWorkflow(plan,worker,{now:()=>plan.start,arm:async()=>false,
    perform:()=>assert.fail("provider must not be called")}),/UNVERIFIED_OR_REUSED/);
});
