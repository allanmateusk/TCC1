import { WorkflowEntrypoint, DurableObject } from "cloudflare:workers";
import { armState, binding, claimState, pin, provider, runCutoffWorkflow, stopExact, verifyTerminal } from "./batch-guard.mjs";

// Candidate is not armed and has no route. Do not fill from event data.
const APPROVED=null;
const noRetry={retries:{limit:0,delay:"1 second"},timeout:"45 seconds"};
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function bounded(task) {
  let timer;
  return Promise.race([task,new Promise(resolve=>{timer=setTimeout(()=>resolve(false),3000);})])
    .finally(()=>clearTimeout(timer));
}

export class BatchStopBarrier extends DurableObject {
  async arm(raw) {
    const plan=pin(APPROVED,raw,raw?.batch);
    return armState(this.ctx.storage,plan,Date.now);
  }
  async claim(raw,kind,proof,signature) {
    const plan=pin(APPROVED,raw,raw?.batch);
    if (kind==="terminal") await verifyTerminal(plan,proof,signature,Date.now());
    else if (kind!=="cutoff" || proof!==null || signature!==null) return false;
    return claimState(this.ctx.storage,plan,kind,Date.now());
  }
}

function perform(env,raw,plan,kind,proof=null,signature=null) {
  const barrier=binding(env.BATCH_STOP_BARRIER,plan);
  return stopExact(plan,kind,{request:provider(fetch,env.RUNPOD_BATCH_STOP_TOKEN),
    claim:()=>bounded(barrier.claim(raw,kind,proof,signature)),now:Date.now,pause});
}

export class RunPodBatchCutoff extends WorkflowEntrypoint {
  async run(event,step) {
    const raw=event.payload;
    const plan=pin(APPROVED,raw,event.instanceId);
    if (!this.env.RUNPOD_BATCH_STOP_TOKEN) throw Error("UNARMED_MISSING_SECRET");
    return runCutoffWorkflow(plan,step,{now:Date.now,
      arm:()=>bounded(binding(this.env.BATCH_STOP_BARRIER,plan).arm(raw)),
      perform:()=>perform(this.env,raw,plan,"cutoff")});
  }
}

export class RunPodBatchTerminal extends WorkflowEntrypoint {
  async run(event,step) {
    const body=event.payload;
    if (!body || !["plan","proof","signature"].every(k=>Object.hasOwn(body,k)) || Object.keys(body).length!==3)
      throw Error("INVALID_TERMINAL_PAYLOAD");
    const plan=pin(APPROVED,body.plan,event.instanceId);
    if (!this.env.RUNPOD_BATCH_STOP_TOKEN) throw Error("UNARMED_MISSING_SECRET");
    return step.do("terminal-stop-or-reconcile",noRetry,async()=>{
      // Caller must separately verify all independently read back receipts before signing.
      await verifyTerminal(plan,body.proof,body.signature,Date.now());
      return perform(this.env,body.plan,plan,"terminal",body.proof,body.signature);
    });
  }
}
