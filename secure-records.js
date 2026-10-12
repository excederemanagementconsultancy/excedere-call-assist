/* Password-wrapped AES-GCM record storage. Authentication tokens are never encrypted or exported here. */
(function(root){
 'use strict';
 const PACKET='excedereCRMEncryptionV1';
 const exact=new Set(['excedereCallAssistLeads','excedereCallAssistLeadsBackup','excedereCRMCompanies','excedereCRMCompaniesBackup','excedereCRMTimeline','excedereCRMTimelineBackup','excedereCRMTasks','excedereCRMTasksBackup','excedereCRMPendingSyncV1']);
 const protectedKey=k=>exact.has(k)||k.startsWith('excedereCRMPendingSyncV2:')||k.startsWith('excedereCRMPendingCommandV1:')||k.startsWith('excedereCRMDraftV1:')||k.startsWith('excedereCRMSyncAckV2:');
 const utf8=new TextEncoder(),text=new TextDecoder();
 const encode=bytes=>{const data=new Uint8Array(bytes);let value='';for(let i=0;i<data.length;i+=8192)value+=String.fromCharCode(...data.subarray(i,i+8192));return btoa(value);};
 const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 class Vault{
  constructor({storage,crypto,allowed=()=>true}){
   this.storage=storage;this.crypto=crypto;this.allowed=allowed;this.owner=null;this.key=null;
   this.values=new Map();this.envelopes=new Map();this.queue=Promise.resolve();this.busy=0;this.failure=null;this.dirty=new Map();
  }
  async derive(password,salt,iterations){
   const material=await this.crypto.subtle.importKey('raw',utf8.encode(password),'PBKDF2',false,['deriveKey']);
   return this.crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:decode(salt),iterations},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  async encrypt(raw,key=this.key,aad='record'){
   const iv=this.crypto.getRandomValues(new Uint8Array(12));
   const cipher=await this.crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf8.encode(aad)},key,utf8.encode(raw));
   return {iv:encode(iv),cipher:encode(cipher)};
  }
  async decrypt(envelope,key=this.key,aad='record'){
   return text.decode(await this.crypto.subtle.decrypt({name:'AES-GCM',iv:decode(envelope.iv),additionalData:utf8.encode(aad)},key,decode(envelope.cipher)));
  }
  async unlock(password,owner){
   if(typeof password!=='string'||!password||!owner)throw new Error('Sign in again to unlock protected CRM records.');
   const cachedOwner=this.storage.getItem('excedereCRMCacheOwnerV1');
   if(cachedOwner&&cachedOwner!==owner)throw new Error('Existing CRM cache belongs to another account.');
   const raw=this.storage.getItem(PACKET);let packet=raw?JSON.parse(raw):null;let key;
   if(packet){
    if(packet.version!==1||packet.ownerId!==owner)throw new Error('Encrypted CRM records belong to another account.');
    const wrapping=await this.derive(password,packet.salt,packet.iterations);
    let material;
    try{material=decode(await this.decrypt(packet.wrappedKey,wrapping,'crm-key:'+owner));}
    catch{throw new Error('CRM records could not be unlocked. Records were retained; use the original password or verified recovery export.');}
    key=await this.crypto.subtle.importKey('raw',material,{name:'AES-GCM'},false,['encrypt','decrypt']);
   }else{
    const salt=encode(this.crypto.getRandomValues(new Uint8Array(16)));
    const wrapping=await this.derive(password,salt,600000);
    const material=this.crypto.getRandomValues(new Uint8Array(32));
    const wrappedKey=await this.encrypt(encode(material),wrapping,'crm-key:'+owner);
    key=await this.crypto.subtle.importKey('raw',material,{name:'AES-GCM'},false,['encrypt','decrypt']);
    packet={version:1,ownerId:owner,salt,iterations:600000,wrappedKey};
   }
   // Decrypt/validate the complete existing set before any storage conversion.
   const values=new Map(),existingEnvelopes=new Map();
   for(let i=0;i<this.storage.length;i++){
    const name=this.storage.key(i);if(!protectedKey(name))continue;
    const entry=this.storage.getItem(name);let parsed;
    try{parsed=JSON.parse(entry);}catch{throw new Error('A CRM record cache is malformed. Original bytes were retained.');}
    if(parsed?.format==='excedere-encrypted-record'){
     if(parsed.ownerId!==owner)throw new Error('Record ownership mismatch.');
     values.set(name,await this.decrypt(parsed,key,owner+':'+name));existingEnvelopes.set(name,entry);
    }else values.set(name,entry);
   }
   const converted=new Map();
   for(const [name,value]of values){
    if(existingEnvelopes.has(name))continue;
    const envelope={format:'excedere-encrypted-record',version:1,ownerId:owner,...await this.encrypt(value,key,owner+':'+name)};
    if(await this.decrypt(envelope,key,owner+':'+name)!==value)throw new Error('Encrypted record verification failed.');
    converted.set(name,JSON.stringify(envelope));
   }
   // Packet precedes conversion so interrupted migration is recoverable with the same password.
   if(!raw)this.storage.setItem(PACKET,JSON.stringify(packet));
   this.owner=owner;this.key=key;this.values=values;this.envelopes=existingEnvelopes;
   for(const [name,envelope]of converted){this.storage.setItem(name,envelope);this.envelopes.set(name,envelope);}
   this.failure=null;
  }
  async adopt(key,owner){
   const packet=JSON.parse(this.storage.getItem(PACKET)||'null');
   if(!key||packet?.ownerId!==owner)throw new Error('CRM records require an authenticated unlock.');
   this.owner=owner;this.key=key;await this.refresh();
  }
  async refresh(){
   if(!this.key)throw new Error('Sign in again to unlock protected CRM records.');
   await this.queue;
   for(let i=0;i<this.storage.length;i++){
    const name=this.storage.key(i);if(!protectedKey(name))continue;
    const raw=this.storage.getItem(name);if(this.envelopes.get(name)===raw)continue;
    const envelope=JSON.parse(raw);
    if(envelope?.format!=='excedere-encrypted-record'||envelope.ownerId!==this.owner)
     throw new Error('An old application wrote an unprotected or mismatched cache. Records were retained; stop and recover.');
    const value=await this.decrypt(envelope,this.key,this.owner+':'+name);
    if(this.dirty.has(name)||this.storage.getItem(name)!==raw)continue;
    this.values.set(name,value);this.envelopes.set(name,raw);
   }
  }
  getItem(name){
   if(!protectedKey(name))return this.storage.getItem(name);
   if(!this.key||!this.allowed())throw new Error('Authenticated CRM unlock required.');
   return this.values.get(name)??null;
  }
  setItem(name,value){
   if(!protectedKey(name)){this.storage.setItem(name,value);return Promise.resolve();}
   if(!this.key||!this.allowed())throw new Error('Authenticated CRM unlock required.');
   value=String(value);this.values.set(name,value);this.dirty.set(name,value);this.busy++;
   const owner=this.owner,key=this.key;
   const job=this.queue.catch(()=>{}).then(async()=>{
    const raw=JSON.stringify({format:'excedere-encrypted-record',version:1,ownerId:owner,...await this.encrypt(value,key,owner+':'+name)});
    this.storage.setItem(name,raw);this.envelopes.set(name,raw);if(this.dirty.get(name)===value)this.dirty.delete(name);
   });
   this.queue=job;
   job.then(()=>{this.busy--;if(!this.dirty.size)this.failure=null;},error=>{this.busy--;this.failure=error;});
   return job;
  }
  async settle(){if(this.failure){for(const [name,value]of [...this.dirty])this.setItem(name,value);}await this.queue;if(this.failure)throw this.failure;}
  seal(){this.key=null;this.owner=null;this.values.clear();this.envelopes.clear();}
 }
 root.ExcedereRecordVault={Vault,protectedKey,PACKET};
 if(typeof module==='object'&&module.exports)module.exports=root.ExcedereRecordVault;
 if(typeof window==='object'&&typeof Storage==='function'){
  const nativeGet=Storage.prototype.getItem,nativeSet=Storage.prototype.setItem;
  const native={get length(){return localStorage.length;},key:i=>localStorage.key(i),getItem:k=>nativeGet.call(localStorage,k),setItem:(k,v)=>nativeSet.call(localStorage,k,v)};
  let migration=false;
  const vault=new Vault({storage:native,crypto:window.crypto,allowed:()=>migration||window.ExcedereRecordAccess?.current()===true});
  Storage.prototype.getItem=function(k){return this===localStorage&&protectedKey(String(k))?vault.getItem(String(k)):nativeGet.call(this,k);};
  Storage.prototype.setItem=function(k,v){return this===localStorage&&protectedKey(String(k))?vault.setItem(String(k),v):nativeSet.call(this,k,v);};

  async function verifyOwner(owner){
   const parsed=JSON.parse(native.getItem('sb-kxxoyhagfmexvnzpuwys-auth-token')||'null');
   const session=parsed?.currentSession||parsed;
   if(!session?.access_token||session.user?.id!==owner||session.expires_at*1000<=Date.now())throw new Error('Authenticated unlock required.');
   const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
   try{
    const response=await fetch('https://kxxoyhagfmexvnzpuwys.supabase.co/auth/v1/user',{
     headers:{apikey:'sb_publishable_2gcvru1GxULE5nCVFNPgQw__vOGbDxx',Authorization:`Bearer ${session.access_token}`},signal:controller.signal
    });
    const user=await response.json();if(!response.ok||user.id!==owner)throw new Error('CRM session could not be verified.');
   }finally{clearTimeout(timer);}
  }
  const api={
   unlock:async(password,owner)=>{
    const rawSession=JSON.parse(native.getItem('sb-kxxoyhagfmexvnzpuwys-auth-token')||'null');
    const session=rawSession?.currentSession||rawSession;
    if(!session?.access_token||session.user?.id!==owner||session.expires_at*1000<=Date.now())throw new Error('Authenticated sign-in is required before cache conversion.');
    if(!native.getItem(PACKET)&&!native.getItem('excedereCRMCacheOwnerV1')){
     const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),30000);
     try{
      const response=await fetch('https://kxxoyhagfmexvnzpuwys.supabase.co/functions/v1/crm-data',{
       method:'POST',headers:{Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},body:JSON.stringify({action:'load'}),signal:controller.signal
      });
      const data=await response.json();if(!response.ok||data.success!==true)throw new Error('Cache ownership could not be verified.');
      for(const [name,key]of Object.entries({leads:'excedereCallAssistLeads',companies:'excedereCRMCompanies',timeline:'excedereCRMTimeline',tasks:'excedereCRMTasks'})){
       if(!Array.isArray(data[name]))throw new Error('Incomplete cache ownership response.');
       const raw=native.getItem(key);
       if(raw!==null&&JSON.stringify(JSON.parse(raw))!==JSON.stringify(data[name]))throw new Error('Unsynchronised legacy cache requires recovery before encryption.');
       const backup=native.getItem(key+'Backup');
       if(backup!==null){
        const archived=JSON.parse(backup),ids=new Set(data[name].map(record=>record.id));
        if(!Array.isArray(archived)||archived.some(record=>!ids.has(record.id)))throw new Error('Archived record ownership requires recovery review before encryption.');
       }
      }
      const latest=JSON.parse(native.getItem('sb-kxxoyhagfmexvnzpuwys-auth-token')||'null');
      if((latest?.currentSession||latest)?.access_token!==session.access_token)throw new Error('Login changed before cache conversion.');
     }finally{clearTimeout(timer);}
    }
    migration=true;try{await vault.unlock(password,owner);}finally{migration=false;}
   },
   open:async owner=>{
    await verifyOwner(owner);
    if(vault.key&&vault.owner===owner){migration=true;await vault.refresh();return;}
    const source=window.opener;
    if(source&&!source.closed){
     let key;try{key=await source.ExcedereSecureRecords?.share(window,owner);}catch{}
     if(key){migration=true;await vault.adopt(key,owner);return;}
    }
    throw new Error('Sign in again to unlock protected CRM records.');
   },
   share:async(target,owner)=>{
    const allowedPaths=['/excedere-crm/','/excedere-crm/excedere-crm-index.html','/excedere-call-assist/','/excedere-call-assist/email.html'];
    if(!vault.key||vault.owner!==owner||!window.ExcedereRecordAccess?.current()||target.location.origin!==location.origin||!allowedPaths.some(p=>target.location.pathname.endsWith(p)))return null;
    // The target independently verifies its server session before requesting this nonextractable key.
    await verifyOwner(owner);return vault.key;
   },
   finish:owner=>{if(vault.owner!==owner)throw new Error("CRM key ownership mismatch.");migration=false;},
   refresh:()=>vault.refresh(),settle:()=>vault.settle(),
   isOpen:owner=>!!vault.key&&vault.owner===owner,
   busy:()=>vault.busy>0||!!vault.failure,
   seal:async()=>{migration=true;try{
    if(vault.key){
     const fields=[];for(const element of document.querySelectorAll("input,textarea,select")){
      if(element.closest("#loginOverlay")||element.type==="password"||/password|token|secret/i.test(element.id+element.name))continue;
      if(element.value)fields.push({id:element.id,name:element.name,type:element.type,value:element.value});
     }
     if(fields.length)await vault.setItem("excedereCRMDraftV1:"+crypto.randomUUID(),JSON.stringify({ownerId:vault.owner,pagePath:location.pathname,fields,capturedAt:new Date().toISOString()}));
    }
    await vault.settle();vault.seal();
   }finally{migration=false;}}
  };
  window.ExcedereSecureRecords=api;
  window.addEventListener('beforeunload',event=>{if(api.busy()){event.preventDefault();event.returnValue='';}});
  const replayed=new WeakSet();
  window.addEventListener('storage',event=>{
   if(!event.key||!protectedKey(event.key)||replayed.has(event))return;
   event.stopImmediatePropagation();
   if(!vault.key)return;
   vault.refresh().then(()=>{
    const replay=new StorageEvent('storage',{key:event.key,oldValue:event.oldValue,newValue:event.newValue,url:event.url,storageArea:localStorage});
    replayed.add(replay);window.dispatchEvent(replay);
   }).catch(()=>{window.ExcedereRecordAccess?.lock();});
  },true);
 }
})(typeof window==='object'?window:globalThis);
