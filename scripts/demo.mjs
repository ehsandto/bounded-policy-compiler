import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {digest,sha} from './check.mjs';
export const action='Use the workshop laser cutter';
export const predicates="staff=The operator is a staff member|supervised=A qualified supervisor is present|revoked=The operator's workshop access is revoked";
try{
 const [mode,address,commit]=process.argv.slice(2);
 if(!['complete','unresolved','badhash','replay','duplicate'].includes(mode)||!/^0x[0-9a-fA-F]{40}$/.test(address??'')||! /^[0-9a-f]{40}$/.test(commit??''))throw Error('Demo context');
 const nonce=mode==='replay'?'demo-complete':'demo-'+mode;
 const path=mode==='unresolved'?'examples/unresolved-policy.txt':'examples/workshop-policy.txt';
 const hash=mode==='badhash'?'f'.repeat(64):sha(fs.readFileSync(path));
 console.log(JSON.stringify({mode,attempt_id:digest({contract:address,creator:'0x7a413BB4AB62E31d62d4cD9efC8C8a8Dae37FB42',nonce})}));
 const args=[nonce,action,predicates,'ehsandto','bounded-policy-compiler',commit,path,hash];
 const r=spawnSync(process.execPath,['scripts/run-cli.cjs','write',address,'compile_policy','--args',...args],{windowsHide:true,stdio:'inherit'});
 process.exitCode=r.status??1;
}catch{console.error('Sanitized demo failure; inspect history before resending');process.exitCode=1;}
