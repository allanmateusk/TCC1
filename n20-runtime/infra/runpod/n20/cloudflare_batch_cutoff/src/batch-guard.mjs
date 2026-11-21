import { transport } from "./runpod-transport.mjs";

const HOUR=3600000;
export const SHORT_MODE="qualification-60m-two-case";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ID=/^[A-Za-z0-9_-]{2,128}$/;
const SHA=/^[0-9a-f]{64}$/;
const GIT=/^[0-9a-f]{40}$/;
const keys=["batch","pod","owner","datacenter","name","startedAt","stopAt","deadline","gitSha","profileSha256","terminalPubKey"];
const exact=(record,fields)=>record && typeof record==="object" && !Array.isArray(record) &&
  Object.keys(record).length===fields.length && fields.every(k=>Object.hasOwn(record,k));
const b64=/^[A-Za-z0-9_-]+$/;
const rawB64=(value,n)=>{
  if (typeof value!=="string" || !b64.test(value)) throw Error("INVALID_SIGNED_TERMINAL");
  const encoded=value.replace(/-/g,"+").replace(/_/g,"/");
  const out=Uint8Array.from(atob(encoded), c=>c.charCodeAt(0));
  if (out.length!==n || btoa(String.fromCharCode(...out)).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")!==value)
    throw Error("INVALID_SIGNED_TERMINAL");
  return out;
};

export function utc(value) {
  if (typeof value!=="string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
    throw Error("INVALID_UTC");
  const ms=Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString()!==value) throw Error("INVALID_UTC");
  return ms;
}
const planKeys=p=>p?.qualificationMode===SHORT_MODE?[...keys,"qualificationMode"]:keys;
export function pin(raw,payload,instance,expectedMode=null) {
  const fields=planKeys(raw);
  if (!exact(raw,fields) || !exact(payload,fields) || !fields.every(k=>payload[k]===raw[k]) ||
      ![null,SHORT_MODE].includes(expectedMode) || (raw.qualificationMode??null)!==expectedMode ||
      !UUID.test(raw.batch) || raw.batch!==instance || ![raw.pod,raw.owner,raw.datacenter].every(v=>typeof v==="string" && ID.test(v)) ||
      typeof raw.name!=="string" || !/^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$/.test(raw.name) ||
      typeof raw.gitSha!=="string" || !GIT.test(raw.gitSha) || typeof raw.profileSha256!=="string" || !SHA.test(raw.profileSha256))
    throw Error("DISARMED_OR_WRONG_BATCH");
  if (raw.terminalPubKey!==null) rawB64(raw.terminalPubKey,32);
  const start=utc(raw.startedAt), wake=utc(raw.stopAt), end=utc(raw.deadline);
  const short=expectedMode===SHORT_MODE;
  if (short ? (end-start!==HOUR || wake-start!==55*60000 || raw.terminalPubKey!==null)
            : (end-start<4*HOUR || end-start>7*HOUR || end-wake!==300000))
    throw Error("UNAPPROVED_BATCH_WINDOW");
  return Object.freeze({...Object.fromEntries(fields.map(k=>[k,raw[k]])),start,wake,end});
}
export function planId(plan) { return JSON.stringify(planKeys(plan).map(k=>plan[k])); }
export function armTime(plan,now) {
  if (!validArm(plan,now)) throw Error("ARM_WITHIN_FIVE_MINUTES");
}
export async function armState(store,plan,now) {
  return store.transaction(async txn=>{
    armTime(plan,now());
    const id=planId(plan), prior=await txn.get("batch-plan");
    const original=await txn.get("first-armed-at-ms");
    if (prior!==undefined) return prior===id && validArm(plan,original)?original:false;
    if (original!==undefined) return false;
    const at=now();
    armTime(plan,at);
    await txn.put("batch-plan",id);
    await txn.put("first-armed-at-ms",at);
    armTime(plan,now());
    return at;
  });
}
const validArm=(p,t)=>Number.isSafeInteger(t) && p.start<=t && t<=p.start+300000 && t<p.wake;
export async function claimState(store,plan,kind,now) {
  if (!eligible(plan,kind,now)) return false;
  return store.transaction(async txn=>{
    if (await txn.get("batch-plan")!==planId(plan) || !validArm(plan,await txn.get("first-armed-at-ms")) ||
        await txn.get("stop-claimed")!==undefined) return false;
    await txn.put("stop-claimed",{batch:plan.batch,kind,at:now});
    return true;
  });
}
const signedFields=["schema","batch","pod","owner","gitSha","profileSha256","verifiedCases","receiptSetSha256","observedAt"];
export function terminalBytes(data){return new TextEncoder().encode(JSON.stringify(signedFields.map(k=>data[k])));}
export async function verifyTerminal(plan,proof,signature,now) {
  if (plan.terminalPubKey===null || !exact(proof,signedFields) || proof.schema!=="tcc-batch-early-stop/v1" ||
      !["batch","pod","owner","gitSha","profileSha256"].every(k=>proof[k]===plan[k]) ||
      proof.verifiedCases!==20 || typeof proof.receiptSetSha256!=="string" || !SHA.test(proof.receiptSetSha256))
    throw Error("INVALID_SIGNED_TERMINAL");
  const at=utc(proof.observedAt);
  if (!(at>=plan.start && at<=now && now-at<=60000 && now<plan.end)) throw Error("STALE_SIGNED_TERMINAL");
  const key=await crypto.subtle.importKey("raw",rawB64(plan.terminalPubKey,32),"Ed25519",false,["verify"]);
  if (!await crypto.subtle.verify("Ed25519",key,rawB64(signature,64),terminalBytes(proof)))
    throw Error("INVALID_SIGNED_TERMINAL");
}
const eligible=(p,kind,now)=>(kind==="cutoff" && now>=p.wake || kind==="terminal" && now>=p.start) && now<p.end;
const fixed = "https://api.runpod.io/v2";
export async function stopExact(plan,kind,{request,claim,now,pause}) {
  const outcome=(state,reason)=>({state,reason,batch:plan.batch,pod:plan.pod,source:kind});
  const manual=reason=>outcome("MANUAL_REQUIRED",reason);
  const exited=()=>outcome("STOP_CONFIRMED",now()>=plan.end?"EXITED_LATE":"EXITED");
  if (!(kind==="cutoff" && now()>=plan.wake || kind==="terminal" && now()>=plan.start)) return manual("EARLY_WAKE");
  const rpc=async (path,method="GET")=>{try{return await request(fixed+path,method);}catch{return null;}};
  if ((await rpc("/account"))?.data?.id!==plan.owner) return manual("OWNER_UNVERIFIED");
  const path="/pods/"+encodeURIComponent(plan.pod);
  async function read() {
    const x=await rpc(path);
    if (x?.status===404) return "MISSING";
    if (x?.status!==200) return "UNKNOWN";
    const d=x.data;
    if (d?.id!==plan.pod || d?.name!==plan.name || d?.dataCenterId!==plan.datacenter || d?.cloud!=="SECURE")
      return "WRONG_TARGET";
    if (d.status==="EXITED") return "EXITED";
    if (d.status==="RUNNING" && Array.isArray(d.actions) && d.actions.includes("stop")) return "RUNNING";
    return "UNEXPECTED_STATE";
  }
  const status=await read();
  if (status==="EXITED") return exited();
  if (status!=="RUNNING") return manual(status);
  if (!eligible(plan,kind,now())) return manual("DEADLINE_PASSED");
  let owns=false;
  try { owns=await claim()===true; } catch { /* ambiguous durable decision: GET only */ }
  if (owns && eligible(plan,kind,now())) await rpc(path+"/action","POST");
  for (let i=0;i<4;i++){
    const current=await read();
    if (current==="EXITED") return exited();
    if (!["RUNNING","UNKNOWN"].includes(current)) return manual(current);
    if (i<3 && now()<plan.end) await pause(1000); else break;
  }
  return manual(owns?"STOP_NOT_CONFIRMED":"CLAIM_NOT_GRANTED_GET_ONLY");
}
export function binding(stub,plan) { return stub.getByName(plan.owner+":"+plan.pod); }
export function provider(fetcher,token){return transport(fetcher,token);}


export async function runCutoffWorkflow(plan,step,{now,arm,perform,workerVersion}) {
  const noRetry={retries:{limit:0,delay:"1 second"},timeout:"45 seconds"};
  await step.do("bind-exact-batch",noRetry,async()=>{
    armTime(plan,now());
    if (typeof workerVersion!=="string" ||
        !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(workerVersion))
      throw Error("UNVERIFIED_RUNTIME_VERSION");
    const armedAtMs=await arm();
    if (!validArm(plan,armedAtMs) || armedAtMs>now()) throw Error("UNVERIFIED_OR_REUSED_POD_BINDING");
    return {batch:plan.batch,pod:plan.pod,armedAtMs,workerVersion,stopAt:plan.stopAt,deadline:plan.deadline,
            gitSha:plan.gitSha,profileSha256:plan.profileSha256,
            ...(plan.qualificationMode===SHORT_MODE?{qualificationMode:SHORT_MODE}:{})};
  });
  await step.sleepUntil("absolute-batch-cutoff",new Date(plan.wake));
  return step.do("cutoff-stop-or-reconcile",noRetry,perform);
}
