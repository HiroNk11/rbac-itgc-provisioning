export const roles=['Reader','Operator','Approver','Administrator','Auditor'];
export const operations=['Create','ReplaceRoles','Disable'];
export const genesis='0'.repeat(64);
export function normalize(input){
 const {externalId,userId,operation,roles:selected,expectedVersion,reason,actorId}=input;
 if([externalId,userId,reason,actorId].some(v=>typeof v!=='string'||!v.trim())||externalId.length>100||userId.length>100||reason.length>1000||actorId.length>200||!operations.includes(operation)||!Number.isInteger(expectedVersion)||expectedVersion<0||expectedVersion>2147483647||!Array.isArray(selected)||selected.length>5||selected.some(r=>!roles.includes(r)))throw Error('INVALID_REQUEST');
 if(operation==='Disable'&&selected.length)throw Error('DISABLE_REQUIRES_EMPTY_ROLES');
 if(operation!=='Disable'&&!selected.length)throw Error('ROLES_REQUIRED');
 return {externalId,userId,operation,roles:roles.filter(r=>selected.includes(r)),expectedVersion,reason,actorId};
}
export function decision(selected){
 if(selected.includes('Operator')&&selected.includes('Approver'))return 'SOD_OPERATOR_APPROVER';
 if(selected.includes('Administrator')&&selected.includes('Auditor'))return 'SOD_ADMINISTRATOR_AUDITOR';
 return null;
}
export async function digest(payload){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(payload))))).map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();}
export function hashPayload(e){return {schema:'rbac-browser-demo-v1',sequence:e.sequence,requestId:e.requestId,timestamp:e.timestamp,actorId:e.actorId,userId:e.userId,operation:e.operation,requestedRoles:e.requestedRoles,before:null,after:null,outcome:e.outcome,reason:e.reason,policyVersion:'sod-v1',previousHash:e.previousHash,hash:''};}
export function empty(){return {requests:[],audit:[]};}
export async function submit(state,input,now=new Date(),id=crypto.randomUUID()){
 let command;try{command=normalize(input);}catch(e){return {state,status:400,code:e.message};}
 const previous=state.requests.find(r=>r.command.externalId===command.externalId);
 if(previous){const same=JSON.stringify(previous.command)===JSON.stringify(command);return {state,status:same?202:409,code:same?'IDEMPOTENT_REPLAY':'IDEMPOTENCY_KEY_REUSED',request:same?previous:undefined};}
 if(state.requests.length>=100)return {state,status:429,code:'DEMO_LIMIT'};
 const rejectionCode=decision(command.roles);
 const request={id,command,receivedAt:now.toISOString(),status:rejectionCode?'Rejected':'Pending',rejectionCode};
 const event={sequence:state.audit.length+1,requestId:id,timestamp:request.receivedAt,actorId:command.actorId,userId:command.userId,operation:command.operation,requestedRoles:[...command.roles],outcome:rejectionCode||'REQUEST_RECEIVED',reason:command.reason,previousHash:state.audit.at(-1)?.hash||genesis};
 event.hash=await digest(hashPayload(event));
 return {state:{requests:[...state.requests,request],audit:[...state.audit,event]},status:202,code:rejectionCode||'REQUEST_RECEIVED',request};
}
export async function verify(events){
 let previousHash=genesis;
 for(let i=0;i<events.length;i++){const event=events[i];if(event.sequence!==i+1||event.previousHash!==previousHash||event.hash!==await digest(hashPayload(event)))return {valid:false,sequence:i+1};previousHash=event.hash;}
 return {valid:true,count:events.length};
}
