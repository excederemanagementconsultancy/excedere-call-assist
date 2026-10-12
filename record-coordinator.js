/* Durable, account-bound record saves serialised across same-origin tabs. */
(function(root){
 "use strict";
 const GROUPS=["companies","leads","timeline","tasks"];
 const PREFIX="excedereCRMPendingSyncV2:";
 const ACK="excedereCRMSyncAckV2:";
 const MISSING=Symbol("missing");
 const clone=v=>JSON.parse(JSON.stringify(v));
 const equal=(a,b)=>a===MISSING||b===MISSING?a===b:JSON.stringify(a)===JSON.stringify(b);
 function mergeValue(base,local,remote,path){
  if(equal(local,base))return remote;
  if(equal(remote,base)||equal(local,remote))return local;
  if(base!==MISSING&&local!==MISSING&&remote!==MISSING&&base&&local&&remote&&
     !Array.isArray(base)&&!Array.isArray(local)&&!Array.isArray(remote)&&
     typeof base==='object'&&typeof local==='object'&&typeof remote==='object'){
   const result={};
   for(const key of new Set([...Object.keys(base),...Object.keys(local),...Object.keys(remote)])){
    const get=(o,k)=>Object.prototype.hasOwnProperty.call(o,k)?o[k]:MISSING;
    const value=mergeValue(get(base,key),get(local,key),get(remote,key),path+'.'+key);
    if(value!==MISSING)Object.defineProperty(result,key,{value,enumerable:true,writable:true,configurable:true});
   }
   return result;
  }
  // Preserve independently appended activity entries without duplicating them.
  if(Array.isArray(base)&&Array.isArray(local)&&Array.isArray(remote)&&
     equal(local.slice(0,base.length),base)&&equal(remote.slice(0,base.length),base)){
   const result=clone(remote);
   for(const item of local.slice(base.length))if(!result.some(existing=>equal(existing,item)))result.push(clone(item));
   return result;
  }
  const error=new Error('Concurrent CRM edits conflict. Both versions were retained for recovery.');
  error.code='CRM_CONFLICT';error.path=path;throw error;
 }
 function validate(records){
  for(const group of GROUPS){
   if(!Array.isArray(records?.[group]))throw new Error('Incomplete CRM record snapshot.');
   const ids=new Set();
   for(const record of records[group]){
    if(!record || typeof record.id!=='string' || !record.id || ids.has(record.id))
     throw new Error('Missing or duplicate CRM record identifier.');
    ids.add(record.id);
   }
  }
 }
 function merge(base,local,remote){
  validate(base);validate(local);validate(remote);
  const result={};
  for(const group of GROUPS){
   const maps=[base,local,remote].map(s=>new Map(s[group].map(r=>[r.id,r])));
   const ids=new Set([...remote[group].map(r=>r.id),...local[group].map(r=>r.id),...base[group].map(r=>r.id)]);
   result[group]=[];
   for(const id of ids){
    const [b,l,r]=maps.map(m=>m.has(id)?m.get(id):MISSING);
    const value=mergeValue(b,l,r,group+'.'+id);
    if(value!==MISSING)result[group].push(clone(value));
   }
  }
  return result;
 }
 class Coordinator{
  constructor(options){
   this.options=options;this.storage=options.storage;this.id=options.id;
   this.key=PREFIX+this.id;this.owner=options.owner;this.base=clone(options.base);validate(this.base);
   this.revision=0;this.promise=null;this.persistPromise=Promise.resolve();this.persisting=0;this.localError=null;
  }
  entries(){
   const rows=[],receipts=[];
   const read=key=>{
    const raw=this.storage.getItem(key);
    if(raw===null){const error=new Error('Shared encrypted records require refresh.');error.code='CRM_LOCAL_REFRESH';throw error;}
    return JSON.parse(raw);
   };
   for(let i=0;i<this.storage.length;i++){
    const key=this.storage.key(i);
    if(key?.startsWith(ACK)){
     const receipt=read(key);
     if(receipt.ownerId!==this.owner)throw new Error('Another account has a CRM recovery receipt.');
     validate(receipt.accepted);validate(receipt.snapshot);receipts.push(receipt);
    }
   }
   for(let i=0;i<this.storage.length;i++){
    const key=this.storage.key(i);
    if(!key?.startsWith(PREFIX))continue;
    const entry=read(key);
    if(entry.version!==2||typeof entry.pending!=='boolean')throw new Error('Invalid CRM recovery entry; retained unchanged.');
    if(entry.pending){
     if(entry.ownerId!==this.owner)throw new Error('Another account has pending CRM records.');
     validate(entry.base);validate(entry.records);
     const receipt=receipts.filter(r=>r.tabId===entry.tabId&&r.revision<=entry.revision).sort((a,b)=>b.revision-a.revision)[0];
     if(receipt?.revision===entry.revision)continue;
     rows.push({key,entry:{...entry,base:receipt && receipt.revision>(entry.basedOnReceipt||0)?receipt.accepted:entry.base}});
    }
   }
   for(let i=0;i<this.storage.length;i++){
    const key=this.storage.key(i);if(!key?.startsWith('excedereCRMPendingCommandV1:'))continue;
    const command=read(key);if(command.pending){const error=new Error('A CRM command remains pending. Recover it before further writes.');error.code='CRM_PENDING_COMMAND';throw error;}
   }
   const legacy=JSON.parse(this.storage.getItem('excedereCRMPendingSyncV1')||'null');
   if(legacy?.pending)throw new Error('A legacy pending snapshot requires recovery review before cloud writes.');
   return rows;
  }
  capture(records){
   if(!this.options.allowed())throw new Error('Authenticated CRM access is required.');
   validate(records);
   const existing=JSON.parse(this.storage.getItem(this.key)||'null');
   const ownReceipt=existing?JSON.parse(this.storage.getItem(ACK+this.id+":"+existing.revision)||"null"):null;
   const alreadyAccepted=ownReceipt?.ownerId===this.owner&&ownReceipt.revision===existing?.revision;
   const base=existing?.pending&&!alreadyAccepted?existing.base:this.base;
   const basedOnReceipt=alreadyAccepted?existing.revision:(existing?.basedOnReceipt||0);
   if(equal(base,records)&&!existing?.pending)return;
   const revision=++this.revision;
   // Synchronous durable write precedes all network work. Each tab has its own key.
   const result=this.storage.setItem(this.key,JSON.stringify({version:2,ownerId:this.owner,
    tabId:this.id,revision,pending:true,base,basedOnReceipt,records:clone(records)}));
   if(result && typeof result.then==="function"){
    this.persisting++;this.persistPromise=Promise.resolve(result);
    this.persistPromise.then(()=>{this.persisting--;this.localError=null;},error=>{this.persisting--;this.localError=error;});
   }
   return this.persistPromise;
  }
  pending(){try{return this.persisting>0||!!this.localError||this.entries().length>0;}catch(error){if(error.code==="CRM_LOCAL_REFRESH")return true;throw error;}}
  flush(){
   if(this.promise)return this.promise;
   if(!this.options.lock) return Promise.reject(new Error('This browser cannot safely coordinate CRM tabs. Records remain pending.'));
   this.promise=this.options.lock('excedere-crm-record-writes',async()=>{
    await this.persistPromise;
    if(this.options.ready)await this.options.ready();
    if(!this.options.allowed())throw new Error('Authenticated CRM access is required.');
    let rows;
    for(let attempt=0;attempt<5;attempt++){
     try{rows=this.entries();break;}catch(error){
      if(error.code!=="CRM_LOCAL_REFRESH"||!this.options.ready||attempt===4)throw error;
      await this.options.ready();
     }
    }
    if(!rows.length)return null;
    let snapshot=await this.options.read();validate(snapshot);
    const expectedRevision=snapshot.revision;
    for(const {entry} of rows)snapshot=merge(entry.base,entry.records,snapshot);
    if(!this.options.allowed())throw new Error('Login changed before saving.');
    const saved=await this.options.write(clone(snapshot),expectedRevision);
    if(saved?.revision!==undefined)snapshot.revision=saved.revision;
    // Immutable receipts acknowledge a captured revision. A flusher never rewrites another tab's journal.
    for(const {entry} of rows){
     await this.storage.setItem(ACK+entry.tabId+":"+entry.revision,JSON.stringify({
      version:2,ownerId:this.owner,tabId:entry.tabId,revision:entry.revision,
      accepted:entry.records,snapshot
     }));
    }
    if(this.options.ready)await this.options.ready();
    const ownRows=this.entries().filter(row=>row.entry.tabId===this.id);
    const own=JSON.parse(this.storage.getItem(this.key)||"null");
    this.base=clone(ownRows.length?ownRows[0].entry.base:(own?.records||this.base));
    // Only canonical saved records enter the shared cache. Pending edits remain in journals.
    if(this.options.cache)await this.options.cache(clone(snapshot));
    if(this.options.accept && !ownRows.length)this.options.accept(clone(snapshot));
    return clone(snapshot);
   });
   const current=this.promise;
   current.then(()=>{if(this.promise===current)this.promise=null;},()=>{if(this.promise===current)this.promise=null;});
   return current;
  }
 }
 root.ExcedereRecordCoordinator={Coordinator,merge,validate,PREFIX,ACK};
 if(typeof module==='object'&&module.exports)module.exports=root.ExcedereRecordCoordinator;
})(typeof window==='object'?window:globalThis);
/* Browser adapter: application record caches are never used as save acknowledgements. */
if(typeof window==='object'){
 window.ExcedereRecordCoordinator.browser=function(base,accept){
  const storage=window.localStorage;
  const owner=storage.getItem('excedereCRMCacheOwnerV1');
  const keys={companies:'excedereCRMCompanies',leads:'excedereCallAssistLeads',timeline:'excedereCRMTimeline',tasks:'excedereCRMTasks'};
  async function request(action,records){
   const validated=await window.ExcedereRecordAccess.authorise();
   if(validated!==owner)throw new Error('CRM account changed.');
   const parsed=JSON.parse(storage.getItem('sb-kxxoyhagfmexvnzpuwys-auth-token')||'null');
   const session=parsed?.currentSession||parsed;
   const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),30000);
   try{
    const response=await fetch('https://kxxoyhagfmexvnzpuwys.supabase.co/functions/v1/crm-data',{
     method:'POST',headers:{Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},
     body:JSON.stringify({action,...records}),signal:abort.signal
    });
    const result=await response.json();
    if(!response.ok||result.success!==true){const error=new Error('CRM cloud request failed; pending records retained.');if(response.status===409)error.code='CRM_VERSION_CONFLICT';throw error;}
    return result;
   }finally{clearTimeout(timer);}
  }
  return new window.ExcedereRecordCoordinator.Coordinator({
   storage,owner,id:crypto.randomUUID(),base,
   allowed:()=>window.ExcedereRecordAccess.current(),
   lock:navigator.locks?.request?navigator.locks.request.bind(navigator.locks):null,
   read:()=>request('load'),write:(snapshot,revision)=>{
    if(typeof revision!=='string'||!/^\d+$/.test(revision))throw new Error('CRM backend version protection is unavailable; changes retained.');
    return request('sync',{...snapshot,expectedRevision:revision,requestId:crypto.randomUUID()});
   },accept,
   ready:()=>window.ExcedereSecureRecords?.refresh(),
   cache:async snapshot=>{for(const [name,key]of Object.entries(keys))await storage.setItem(key,JSON.stringify(snapshot[name]));}
  });
 };
 window.ExcedereRecordCoordinator.cached=function(){
  const result={};
  for(const [name,key]of Object.entries({companies:'excedereCRMCompanies',leads:'excedereCallAssistLeads',timeline:'excedereCRMTimeline',tasks:'excedereCRMTasks'})){
   const raw=localStorage.getItem(key);result[name]=raw===null?[]:JSON.parse(raw);
  }
  return result;
 };
 window.ExcedereRecordCoordinator.connectLeads=function(initial){
  const base=window.ExcedereRecordCoordinator.cached();
  const coordinator=window.ExcedereRecordCoordinator.browser(base);
  let retry=null,delay=1000;
  async function flush(){
   try{
    while(coordinator.pending())await coordinator.flush();delay=1000;
   }catch(error){
    console.error('CRM changes remain pending. '+(error.code==='CRM_CONFLICT'?'Conflicting edits require recovery review.':'The save will retry.'));
    if(error.code!=='CRM_CONFLICT'){clearTimeout(retry);retry=setTimeout(flush,delay);delay=Math.min(delay*2,30000);}
   }
  }
  window.addEventListener('online',flush);
  return {save:records=>{const snapshot=window.ExcedereRecordCoordinator.cached();snapshot.leads=records;coordinator.capture(snapshot);flush();},flush,coordinator};
 };
}
