import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { terminalBytes } from "./src/batch-guard.mjs";

const source=await readFile(new URL("./src/index.mjs",import.meta.url),"utf8");
const guard=new URL("./src/batch-guard.mjs",import.meta.url).href;
const platform="data:text/javascript,"+encodeURIComponent(
  "export class WorkflowEntrypoint {constructor(ctx,env){this.ctx=ctx;this.env=env;}} "+
  "export class DurableObject {constructor(ctx,env){this.ctx=ctx;this.env=env;}}");
const time=Date.parse("2026-01-02T03:04:05.000Z"); // deliberate historical fixture
const iso=t=>new Date(t).toISOString();
const sha=b=>createHash("sha256").update(b).digest("hex");

async function sourceWith(approved) {
  // Substitute only in memory, never in the source or a deployable file.
  assert.equal(source.match(/const APPROVED=null;/g)?.length,1);
  const replaced=source.replace('"cloudflare:workers"',JSON.stringify(platform))
    .replace('"./batch-guard.mjs"',JSON.stringify(guard))
    .replace("const APPROVED=null;", "const APPROVED="+JSON.stringify(approved)+";");
  return import("data:text/javascript,"+encodeURIComponent(replaced));
}

class FixtureStorage {
  entries=new Map();
  writes=[];
  ready=Promise.resolve();
  transaction(action) {
    const run=this.ready.then(()=>action({
      get:async k=>this.entries.get(k),
      put:async (k,v)=>{this.writes.push(k);this.entries.set(k,v);},
    }));
    this.ready=run.catch(()=>{});
    return run;
  }
}
function fixtureProvider(p,store) {
  let state="RUNNING";
  const requests=[];
  const fake=async (url,opts)=>{
    const path=new URL(url).pathname;
    assert.equal(new URL(url).origin,"https://api.runpod.io");
    requests.push([opts.method,path]);
    if (path==="/v2/account" && opts.method==="GET")
      return Response.json({id:p.owner});
    if (path==="/v2/pods/"+p.pod && opts.method==="GET")
      return Response.json({id:p.pod,name:p.name,dataCenterId:p.datacenter,cloud:"SECURE",status:state,actions:["stop"]});
    assert.equal(path,"/v2/pods/"+p.pod+"/action");
    assert.equal(opts.method,"POST");
    assert.deepEqual(JSON.parse(opts.body),{action:"stop"});
    assert.equal(store.entries.get("stop-claimed")?.kind,"terminal","durable claim must precede provider POST");
    state="EXITED";
    return new Response(null,{status:202});
  };
  return {fake,requests};
}
const step={async do(name,opts,run) {
  assert.equal(name,"terminal-stop-or-reconcile");
  assert.equal(opts.retries.limit,0);
  return run();
}};
function plan(pub=null) {
  return {batch:"c6bf221c-7762-4be3-bf5e-b61cd5ab8e44",owner:"fixture-terminal-owner",pod:"fixture-terminal-pod",
     datacenter:"TEST-1",name:"Offline terminal fixture",startedAt:iso(time),stopAt:iso(time+18_000_000),
     deadline:iso(time+18_300_000),gitSha:"7".repeat(40),profileSha256:"8".repeat(64),terminalPubKey:pub};
}
async function key() {
  const material=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
  return {...material,pub:Buffer.from(await crypto.subtle.exportKey("raw",material.publicKey)).toString("base64url")};
}
function mockReceiptSet(n) {
  const ordered=Array.from({length:n},(_,i)=>{
    const key="fixture-case-"+String(i+1).padStart(2,"0");
    const stored=Buffer.from(key);
    const readBack=Buffer.from(stored);
    assert.notEqual(readBack,stored);
    assert.equal(sha(readBack),sha(stored));
    return {key,bytes:readBack.length,sha256:sha(readBack)};
  });
  return {size:ordered.length,digest:sha(JSON.stringify(ordered))};
}
async function certificate(p,k,count,at=time+600_000) {
  const receipts=mockReceiptSet(count);
  const proof={schema:"tcc-batch-early-stop/v1",batch:p.batch,pod:p.pod,owner:p.owner,gitSha:p.gitSha,
    profileSha256:p.profileSha256,verifiedCases:receipts.size,receiptSetSha256:receipts.digest,observedAt:iso(at)};
  return {plan:p,proof,signature:Buffer.from(await crypto.subtle.sign("Ed25519",k.privateKey,terminalBytes(proof)))
    .toString("base64url")};
}
async function context(t,p) {
  const m=await sourceWith(p),store=new FixtureStorage();
  const {fake,requests}=fixtureProvider(p,store);
  t.mock.method(globalThis,"fetch",fake);
  const clock=t.mock.method(Date,"now",()=>time+25);
  const barrier=new m.BatchStopBarrier({storage:store},{});
  const env={RUNPOD_BATCH_STOP_TOKEN:"FAKE_NOT_SECRET",BATCH_STOP_BARRIER:{getByName(name){
    assert.equal(name,p.owner+":"+p.pod);
    return barrier;
  }}};
  const workflow=new m.RunPodBatchTerminal({},env);
  assert.equal(await barrier.arm(p),time+25);
  clock.mock.mockImplementation(()=>time+600_500);
  return {workflow,barrier,store,requests,execute:body=>workflow.run({instanceId:p.batch,payload:body},step)};
}

test("terminal Workflow: 20 verified fixture receipts -> real Ed25519 -> durable claim -> GET-confirmed EXITED",async t=>{
  const k=await key(),p=plan(k.pub),c=await context(t,p);
  const body=await certificate(p,k,20);
  assert.deepEqual(await c.execute(body),{state:"STOP_CONFIRMED",reason:"EXITED",
    batch:p.batch,pod:p.pod,source:"terminal"});
  assert.deepEqual(c.store.writes,["batch-plan","first-armed-at-ms","stop-claimed"]);
  assert.deepEqual(c.requests,[
    ["GET","/v2/account"],["GET","/v2/pods/"+p.pod],["POST","/v2/pods/"+p.pod+"/action"],["GET","/v2/pods/"+p.pod],
  ]);
  assert.equal((await c.execute(body)).state,"STOP_CONFIRMED");
  assert.equal(c.requests.filter(x=>x[0]==="POST").length,1);
  assert.equal(c.store.writes.length,3);
});

test("null signer inhibits all terminal requests and does not consume a claim",async t=>{
  const k=await key(),p=plan(),c=await context(t,p);
  const body=await certificate(p,k,20);
  await assert.rejects(c.execute(body),/INVALID_SIGNED_TERMINAL/);
  await assert.rejects(c.barrier.claim(p,"terminal",body.proof,body.signature),/INVALID_SIGNED_TERMINAL/);
  assert.deepEqual(c.store.writes,["batch-plan","first-armed-at-ms"]);
  assert.deepEqual(c.requests,[]);
});

test("wrong signer, correctly signed 19 receipts, edited digest and stale claim make no writes",async t=>{
  const k=await key(),rogue=await key(),p=plan(k.pub),c=await context(t,p);
  const valid=await certificate(p,k,20);
  const edits={...valid,proof:{...valid.proof,receiptSetSha256:"4".repeat(64)}};
  for(const body of [await certificate(p,rogue,20),await certificate(p,k,19),edits,
    await certificate(p,k,20,time+100_000)]) {
    await assert.rejects(c.execute(body),/INVALID_SIGNED_TERMINAL|STALE_SIGNED_TERMINAL/);
    await assert.rejects(c.barrier.claim(p,"terminal",body.proof,body.signature),/INVALID_SIGNED_TERMINAL|STALE_SIGNED_TERMINAL/);
  }
  assert.deepEqual(c.store.writes,["batch-plan","first-armed-at-ms"]);
  assert.deepEqual(c.requests,[]);
});

test("the real checked-in APPROVED=null rejects even a correctly signed fixture and never touches bindings",async t=>{
  const k=await key(),p=plan(k.pub),m=await sourceWith(null);
  const workflow=new m.RunPodBatchTerminal({},new Proxy({},{
    get(){assert.fail("disarmed Workflow may not consult bindings");},
  }));
  t.mock.method(globalThis,"fetch",()=>assert.fail("disarmed Workflow may not fetch"));
  await assert.rejects(workflow.run({instanceId:p.batch,payload:await certificate(p,k,20)},step),/DISARMED/);
});
