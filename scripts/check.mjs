import fs from 'node:fs';
import crypto from 'node:crypto';
import {createClient} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';
export const canonical=x=>x===null||typeof x!=='object'?JSON.stringify(x).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')):
 Array.isArray(x)?'['+x.map(canonical).join(',')+']':'{'+Object.keys(x).sort().map(k=>canonical(k)+':'+canonical(x[k])).join(',')+'}';
export const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
export const digest=x=>sha(canonical(x));
export async function rpc(method,params){
 const r=await fetch('https://studio.genlayer.com/api',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(20000)});
 if(!r.ok)throw Error('HTTP failure');const p=await r.json();if(p.error||p.result==null)throw Error('RPC failure');return p.result;
}
export const client=createClient({chain:studionet});
export const read=(address,functionName,args)=>client.readContract({address,functionName,args});
if(process.argv[1]?.endsWith('check.mjs'))try{
 const [mode,value,extra]=process.argv.slice(2);
 if(mode==='source'){
  const norm=x=>x.replace(/\r\n/g,'\n').trimEnd()+'\n';
  const actual=norm(Buffer.from(await rpc('gen_getContractCode',[value]),'base64').toString('utf8'));
  const local=norm(fs.readFileSync('contracts/BoundedPolicyCompiler.py','utf8'));
  console.log(JSON.stringify({address:value,source_matches:actual===local,source_sha256:sha(actual)}));if(actual!==local)process.exitCode=1;
 }else if(['success','error'].includes(mode)){
  let tx=await rpc('eth_getTransactionByHash',[value]);
  for(let i=0;tx.status!=='FINALIZED'&&i<15;i++){await new Promise(r=>setTimeout(r,2000));tx=await rpc('eth_getTransactionByHash',[value]);}
  const leader=tx.consensus_data?.leader_receipt?.find(x=>x.mode==='leader'),raw=leader?.genvm_result?.stderr||leader?.result;
  const decoded=typeof raw!=='string'?'':(/^[A-Za-z0-9+/]*={0,2}$/.test(raw)&&raw.length%4===0?Buffer.from(raw,'base64').toString('utf8'):raw);
  console.log(JSON.stringify({hash:value,address:tx.to_address??tx.to,status:tx.status,execution:leader?.execution_result,consensus:tx.result_name,...(extra?{expected_error_matched:decoded.includes(extra)}:{})}));
  if(tx.status!=='FINALIZED'||leader?.execution_result!==(mode==='error'?'ERROR':'SUCCESS')||tx.result_name!=='MAJORITY_AGREE'||(extra&&!decoded.includes(extra)))process.exitCode=1;
 }else if(mode==='attempt'){
  const a=await read(value,'get_attempt',[extra]);const {root,...body}=a;
  if(digest(body)!==root||a.report.binding.attempt!==extra||a.report.config.contract!==value||digest(a.report.config)!==a.report.binding.artifact)throw Error('Attempt binding/root');
  const s=a.report.source,spec=a.report.config.source;
  if(s.url!==spec.url||(s.body&&sha(s.body)!==s.hash))throw Error('Source hash binding');
  if(a.status==='COMPILED'){
   if(s.status!=='OK'||s.http!==200||s.hash!==spec.sha256)throw Error('Bad source compiled');
   const artifact=await read(value,'get_artifact',[a.report.binding.artifact]);const {root:aroot,...compiled}=artifact;
   if(digest(compiled)!==aroot||canonical(compiled)!==canonical({config:a.report.config,source:s,table:a.report.table}))throw Error('Artifact mismatch');
   const n=artifact.config.predicates.length,table=artifact.table;
   if(table.length!==(1<<n)||table.some(x=>!['ALLOW','DENY','CONFLICT','UNKNOWN'].includes(x)))throw Error('Invalid table');
   // Verify all fully known assignments plus three material partial contexts.
   const checks=[...table.map((_,i)=>[(1<<n)-1,i]),[0,0],[4,4],[5,1],[4,0]].filter(([k,v])=>k<(1<<n)&&!(v&~k));
   const results=[];
   for(const [known,values] of checks){
    const r=await read(value,'simulate',[a.report.binding.artifact,aroot,known,values]);
    const indexes=table.map((_,i)=>i).filter(i=>(i&known)===values),labels=indexes.map(i=>table[i]);
    const expected=labels.every(x=>x==='ALLOW')?'ALLOW':labels.every(x=>x==='DENY')?'DENY':'UNRESOLVED';
    if(r.decision!==expected||!r.hypothetical_only||r.root!==aroot||r.artifact!==a.report.binding.artifact||canonical(r.completions)!==canonical(indexes)||canonical(r.labels)!==canonical(labels)||r.has_conflict!==labels.includes('CONFLICT')||r.has_unknown!==labels.includes('UNKNOWN'))throw Error('Partial interpreter mismatch');
    results.push({known,values,decision:r.decision,has_unknown:r.has_unknown});
   }
   console.log(JSON.stringify({attempt:extra,attempt_root:root,status:a.status,artifact:a.report.binding.artifact,artifact_root:aroot,table,query_checks:results}));
  }else if(a.status==='HELD'){
   if(s.status==='OK'||a.report.table.length)throw Error('Held result has a function');
   let rejected=false;try{await read(value,'get_artifact',[a.report.binding.artifact]);}catch(e){if(e.code!==-32000||e.details!=='execution failed')throw e;rejected=true;}
   if(!rejected)throw Error('Held result exposed artifact');
   console.log(JSON.stringify({attempt:extra,attempt_root:root,status:a.status,artifact_absent:true,source_status:s.status}));
  }else throw Error('Unknown attempt status');
 }else throw Error('Unknown mode');
}catch{console.error('Sanitized verification failure; inspect history before rebroadcast');process.exitCode=1;}
