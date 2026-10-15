// One documented write at a time. Preserve every known hash; never silently retry an uncertain broadcast.
import fs from 'node:fs';
import {spawn} from 'node:child_process';
import {rpc} from './check.mjs';
const address='0x3B25560249B8D5b129e69dE0894E072AdB9F3e55',commit='57390a2190c5935792a86bbd6dc3bbfcbdb62902';
const seed=[
 {step:'deploy',hash:'0x9f2f2f134f24780c84c79a467faef6385913840dcdad04f7738dc6bb95380319',status:'FINALIZED',execution:'SUCCESS',consensus:'MAJORITY_AGREE'},
 {step:'complete',hash:'0x71daf1569c2027c12d3e72b429e3d6407217d6cf4639f4789d7e20b3d604eb7c'}
];
const steps=['deploy','complete','unresolved','badhash','replay','duplicate'];
let ledger=fs.existsSync('PROOFS.json')?JSON.parse(fs.readFileSync('PROOFS.json','utf8')):{address,fixture_commit:commit,transactions:seed};
if(ledger.address!==address||ledger.fixture_commit!==commit)throw Error('Proof context mismatch');
const save=()=>fs.writeFileSync('PROOFS.json',JSON.stringify(ledger,null,2)+'\n');
function launch(step){return new Promise((resolve,reject)=>{
 const entry={step,status:'BROADCAST_UNKNOWN'};ledger.transactions.push(entry);save();
 const child=spawn(process.execPath,['--dns-result-order=ipv4first','scripts/demo.mjs',step,address,commit],{windowsHide:true,stdio:['ignore','pipe','pipe']});
 let carry='',known;
 child.stdout.on('data',chunk=>{
  carry+=chunk.toString();const lines=carry.split(/\r?\n/);carry=lines.pop();
  for(const line of lines){const m=line.match(/^BROADCAST_HASH (0x[0-9a-fA-F]{64})$/);
   if(m){if(known&&known!==m[1]){child.kill();reject(Error('Multiple hashes'));return;}
    known=m[1];Object.assign(entry,{hash:known,status:'SUBMITTED'});save();console.log(JSON.stringify({step,broadcast:known}));}
  }
 });
 child.stderr.resume();
 const timer=setTimeout(()=>{child.kill();reject(Error('Child timeout; inspect history'));},150000);
 child.on('error',()=>{clearTimeout(timer);reject(Error('Launch failure'));});
 child.on('close',()=>{clearTimeout(timer);if(!known)reject(Error('Uncertain broadcast; inspect sender history'));else resolve();});
});}
async function verify(entry){
 for(let i=0;i<30;i++){
  const tx=await rpc('eth_getTransactionByHash',[entry.hash]);
  if(tx.status==='FINALIZED'){
   const leader=tx.consensus_data?.leader_receipt?.find(x=>x.mode==='leader');
   const expected=entry.step==='replay'?'Attempt nonce used':entry.step==='duplicate'?'Artifact already compiled':null;
   const raw=leader?.genvm_result?.stderr||leader?.result;
   const decoded=typeof raw==='string'?(/^[A-Za-z0-9+/]*={0,2}$/.test(raw)&&raw.length%4===0?Buffer.from(raw,'base64').toString('utf8'):raw):'';
   if(leader?.execution_result!==(expected?'ERROR':'SUCCESS')||tx.result_name!=='MAJORITY_AGREE'||(expected&&!decoded.includes(expected)))throw Error('Unexpected execution');
   Object.assign(entry,{status:tx.status,execution:leader.execution_result,consensus:tx.result_name,...(expected?{expected_error:expected}:{})});save();console.log(JSON.stringify(entry));return;
  }
  await new Promise(r=>setTimeout(r,4000));
 }
 throw Error('Finalization pending; resume saved hash only');
}
let current;
try{
 save();
 for(const step of steps){
  current=step;let entry=ledger.transactions.find(x=>x.step===step);
  if(!entry){await launch(step);entry=ledger.transactions.find(x=>x.step===step);}
  if(!entry.hash)throw Error('Uncertain broadcast needs manual history check');
  if(entry.status==='FINALIZED'&&entry.execution)continue;
  await verify(entry);
 }
 console.log('All documented transactions finalized with expected execution outcomes.');
}catch{
 console.error(JSON.stringify({stopped_at:current,message:'Stopped safely. Inspect saved receipt/history. No automatic rebroadcast.'}));
 process.exitCode=1;
}
