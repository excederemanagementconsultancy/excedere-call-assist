/* Authentication gate for existing CRM pages. No customer caches are cleared. */
(()=>{
 "use strict";
 const AUTH_KEY="sb-kxxoyhagfmexvnzpuwys-auth-token";
 const OWNER_KEY="excedereCRMCacheOwnerV1";
 const ROOT="https://kxxoyhagfmexvnzpuwys.supabase.co";
 const CRM_URL="https://excederemanagementconsultancy.github.io/excedere-crm/";
 const API_KEY="sb_publishable_2gcvru1GxULE5nCVFNPgQw__vOGbDxx";
 const CACHE_KEYS={leads:"excedereCallAssistLeads",companies:"excedereCRMCompanies",timeline:"excedereCRMTimeline",tasks:"excedereCRMTasks"};
 let allowed=false,owner=null,checking=null,generation=0,verifiedLogin=null;
 function session(){
  try{
   const parsed=JSON.parse(localStorage.getItem(AUTH_KEY)||"null");
   return parsed?.currentSession||parsed;
  }catch{return null;}
 }
 function lock(){
  generation++;allowed=false;
  document.documentElement.removeAttribute("data-crm-authorised");
 }
 async function request(url,token,options={}){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
  try{
   const response=await fetch(url,{...options,signal:controller.signal,headers:{
    apikey:API_KEY,Authorization:`Bearer ${token}`,"Content-Type":"application/json"
   }});
   if(!response.ok) throw new Error("Authentication or recovery check failed.");
   return await response.json();
  }finally{clearTimeout(timer);}
 }
 function sameLogin(a,b){
  if(!a?.user?.id || a.user.id!==b?.user?.id) return false;
  if(a.access_token===b.access_token) return true;
  function sessionId(s){
   try{
    const part=s.access_token.split(".")[1].replace(/-/g,"+").replace(/_/g,"/");
    const claims=JSON.parse(atob(part));
    return claims.sub===s.user.id && typeof claims.session_id==="string" ? claims.session_id : null;
   }catch{return null;}
  }
  const id=sessionId(a);
  return !!id && id===sessionId(b);
 }
 function assertLogin(credentials,version){
  const latest=session();
  if(version!==generation || !sameLogin(credentials,latest) || latest.expires_at*1000<=Date.now())
   throw new Error("Login changed during verification.");
  return latest;
 }
 async function verify(){
  // Routine server checks leave an already verified, unexpired login usable.
  if(!current()) lock();
  const version=generation;
  const credentials=session();
  if(!credentials?.access_token || !credentials.expires_at || credentials.expires_at*1000<=Date.now())
   throw new Error("A valid CRM login is required.");
  let verified=credentials;
  let user;
  // A refresh can rotate the token while the server check is in flight.
  // Verify the replacement token; never accept a different login session.
  for(let attempt=0;attempt<3;attempt++){
   user=await request(ROOT+"/auth/v1/user",verified.access_token);
   if(!user?.id || user.id!==credentials.user?.id) throw new Error("CRM account could not be verified.");
   const latest=assertLogin(credentials,version);
   if(latest.access_token===verified.access_token) break;
   verified=latest;
   if(attempt===2) throw new Error("CRM login refresh did not settle; verification required.");
  }
  if(document.documentElement.dataset.crmVault==="required"&&!window.ExcedereSecureRecords)throw new Error("Protected CRM storage failed to load; access remains locked.");
  if(!user?.id || (credentials.user?.id && credentials.user.id!==user.id))
   throw new Error("CRM account could not be verified.");
  if(window.ExcedereSecureRecords)await window.ExcedereSecureRecords.open(user.id);
  const cacheOwner=localStorage.getItem(OWNER_KEY);
  if(cacheOwner && cacheOwner!==user.id)
   throw new Error("This browser contains another account's CRM cache. Records were retained; use the original account or an isolated browser profile.");
  if(!cacheOwner){
   // Claim a legacy cache only when the authenticated cloud snapshot matches it.
   const result=await request(ROOT+"/functions/v1/crm-data",credentials.access_token,{
    method:"POST",body:JSON.stringify({action:"load"})
   });
   if(result.success!==true) throw new Error("CRM cache ownership could not be verified.");
   for(const [name,key] of Object.entries(CACHE_KEYS)){
    if(!Array.isArray(result[name])) throw new Error("Incomplete ownership response.");
    const raw=localStorage.getItem(key);
    if(raw!==null && JSON.stringify(JSON.parse(raw))!==JSON.stringify(result[name]))
     throw new Error("Local and cloud CRM records differ. Recovery review is required before granting access.");
   }
   const pendingRaw=localStorage.getItem("excedereCRMPendingSyncV1");
   if(pendingRaw){
    const pending=JSON.parse(pendingRaw);
    if(pending.pending && pending.ownerId!==user.id)
     throw new Error("Pending records belong to another account.");
   }
   // Recheck after the async read; never claim a changed session or cache.
   const latest=session();
   assertLogin(credentials,version);
   for(const [name,key] of Object.entries(CACHE_KEYS)){
    const raw=localStorage.getItem(key);
    if(raw!==null && JSON.stringify(JSON.parse(raw))!==JSON.stringify(result[name]))
     throw new Error("CRM cache changed during verification; records were retained.");
   }
   localStorage.setItem(OWNER_KEY,user.id);
  }
  const latest=session();
  assertLogin(credentials,version);
  if(latest.access_token!==verified.access_token){
   const refreshedUser=await request(ROOT+"/auth/v1/user",latest.access_token);
   if(refreshedUser?.id!==user.id) throw new Error("CRM account could not be verified.");
   const final=assertLogin(credentials,version);
   if(final.access_token!==latest.access_token) throw new Error("CRM login refresh did not settle; verification required.");
  }
  if(owner && owner!==user.id) throw new Error("Account changed; reopen CRM in an isolated profile.");
  owner=user.id;verifiedLogin=session();allowed=true;
  window.ExcedereSecureRecords?.finish(user.id);
  document.documentElement.setAttribute("data-crm-authorised","true");
  return user.id;
 }
 async function authorise(){
  if(checking) return checking;
  checking=verify();
  try{return await checking;}catch(error){
   lock();
   if(window.ExcedereSecureRecords?.isOpen(owner)){
    try{await window.ExcedereSecureRecords.seal();location.replace(CRM_URL);}catch{}
   }
   throw error;
  }finally{checking=null;}
 }
 function current(){
  const s=session();
  return allowed && sameLogin(verifiedLogin,s) && s?.user?.id===owner && s?.expires_at*1000>Date.now() && localStorage.getItem(OWNER_KEY)===owner;
 }
 function recheck(){
  // Revoke visible access immediately if a checked login changes mid-request.
  if(allowed && !current()) lock();
  const credentials=session();
  // Main-page password sign-in owns the initial vault unlock.
  if(document.documentElement.dataset.crmEntry==="main" &&
     !window.ExcedereSecureRecords?.isOpen(credentials?.user?.id)){
   if(!current()) lock();
   return;
  }
  authorise().catch(()=>{
   lock();
   if(document.documentElement.dataset.crmEntry!=="main") location.replace(CRM_URL);
   else if(typeof showLogin==="function") showLogin();
  });
 }
 window.ExcedereRecordAccess={authorise,current,lock};
 for(const event of ["click","submit","input","keydown"])
  document.addEventListener(event,e=>{
   if(!current() && !e.target.closest?.("#loginOverlay")){
    lock();e.preventDefault();e.stopImmediatePropagation();
   }
  },true);
 window.addEventListener("storage",e=>{
  if(e.key===AUTH_KEY || e.key===OWNER_KEY || e.key===null) recheck();
 });
 window.addEventListener("focus",recheck);
 document.addEventListener("visibilitychange",()=>{if(!document.hidden)recheck();});
 setInterval(()=>{if(!current())recheck();},1000);
 // Server revalidation detects revoked sessions while a page stays open.
 setInterval(recheck,30000);
 if(document.documentElement.dataset.crmEntry!=="main"){
  document.addEventListener("DOMContentLoaded",async()=>{
   try{
    await authorise();
    for(const inert of document.querySelectorAll('script[type="application/x-excedere-protected"]')){
     if(!current()) throw new Error("Login changed before page startup.");
     const active=document.createElement("script");active.textContent=inert.textContent;
     inert.replaceWith(active);
    }
    if(document.readyState==="complete") window.dispatchEvent(new Event("load"));
   }catch{lock();location.replace(CRM_URL);}
  });
 }
})();
