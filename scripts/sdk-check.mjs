import assert from 'node:assert/strict';
import {abi} from 'genlayer-js';
const h='a'.repeat(64);
for(const [method,args] of [['compile_policy',['n','Use the workshop laser cutter','staff=The operator is staff','ehsandto','bounded-policy-compiler','a'.repeat(40),'examples/workshop-policy.txt',h]],
 ['get_attempt',[h]],['get_artifact',[h]],['simulate',[h,h,5,1]]]){
 const data=abi.calldata.encode(abi.calldata.makeCalldataObject(method,args,{}));
 assert.deepEqual(abi.calldata.encode(abi.calldata.decode(data)),data);
}
console.log('4 SDK calldata roundtrips passed');
