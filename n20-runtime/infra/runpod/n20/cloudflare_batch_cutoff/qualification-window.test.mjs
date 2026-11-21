import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pin, SHORT_MODE } from "./src/batch-guard.mjs";

const time=Date.parse("2026-01-02T03:04:05.000Z");
const iso=ms=>new Date(time+ms).toISOString();
const raw={batch:"c6bf221c-7762-4be3-bf5e-b61cd5ab8e44",owner:"fixture-owner",pod:"fixture-pod",datacenter:"TEST-1",
  name:"Fixture",startedAt:iso(0),stopAt:iso(3300000),deadline:iso(3600000),gitSha:"7".repeat(40),
  profileSha256:"8".repeat(64),terminalPubKey:null,qualificationMode:SHORT_MODE};
test("short interval is explicit and exact; long lane cannot adopt it",()=>{
  assert.equal(pin(raw,raw,raw.batch,SHORT_MODE).wake,time+3300000);
  assert.throws(()=>pin(raw,raw,raw.batch),/DISARMED/);
  const {qualificationMode,...base}=raw;
  assert.throws(()=>pin(base,base,raw.batch),/WINDOW/);
  assert.throws(()=>pin(base,base,raw.batch,SHORT_MODE),/DISARMED/);
  for(const changes of [{stopAt:iso(3300001)},{deadline:iso(3600001)},{terminalPubKey:"A".repeat(43)}]){
    const bad={...raw,...changes};
    assert.throws(()=>pin(bad,bad,bad.batch,SHORT_MODE));
  }
  const long={...base,stopAt:iso(14400000-300000),deadline:iso(14400000)};
  assert.equal(pin(long,long,long.batch).end,time+14400000);
});
test("separate short Worker has no terminal or public entrypoint",async()=>{
  const short=JSON.parse(await readFile(new URL("./wrangler.qualification.jsonc",import.meta.url),"utf8"));
  assert.equal(short.vars.QUALIFICATION_MODE,SHORT_MODE);
  assert.deepEqual(short.workflows.map(w=>w.class_name),["RunPodBatchCutoff"]);
  assert.equal(short.workers_dev,false);
  assert.equal(short.preview_urls,false);
  assert.deepEqual(short.routes,[]);
  assert.equal(short.triggers,undefined);
});
