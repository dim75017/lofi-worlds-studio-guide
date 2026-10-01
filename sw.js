const BASE=new URL('./',self.location.href),sessions=new Map(),grants=new Map(),pending=new Map();
const publicFiles=new Set(['','index.html','gate.js','gate.css','sw.js','boot.json','favicon.ico','robots.txt','.nojekyll']);
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
const within=url=>url.origin===BASE.origin&&url.pathname.startsWith(BASE.pathname);
const fingerprint=async token=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token))),n=>n.toString(16).padStart(2,'0')).join('');
const parentClient=client=>{if(!client||client.frameType!=='top-level')return false;const u=new URL(client.url);return within(u)&&['','index.html'].includes(u.pathname.slice(BASE.pathname.length))};
function validSession(data){return typeof data.token==='string'&&/^[a-f0-9]{48}$/.test(data.token)&&data.key instanceof CryptoKey&&!data.key.extractable&&data.key.algorithm.name==='AES-GCM'&&data.key.usages.length===1&&data.key.usages[0]==='decrypt'&&data.manifest?.schema===1&&data.manifest.files?.['guide.html']}
self.addEventListener('message',event=>{
 event.waitUntil((async()=>{
  const source=event.source&&await self.clients.get(event.source.id);if(!parentClient(source))return;
  const data=event.data;if(!validSession(data))return;
  const existing=sessions.get(data.token);if(existing&&existing.parentId!==source.id)return;
  if(data.type==='UNLOCK'){
   sessions.set(data.token,{key:data.key,manifest:data.manifest,parentId:source.id});grants.set(source.id,data.token);event.ports[0]?.postMessage({ok:true});
  }else if(data.type==='RESTORE_SESSION'){
   const waiter=pending.get(data.requestId);if(!waiter||waiter.fingerprint!==await fingerprint(data.token))return;
   sessions.set(data.token,{key:data.key,manifest:data.manifest,parentId:source.id});grants.set(source.id,data.token);waiter.resolve(sessions.get(data.token));
  }
 })());
});
async function recover(token){
 if(!/^[a-f0-9]{48}$/.test(token||''))return null;
 const known=sessions.get(token);if(known){if(await self.clients.get(known.parentId))return known;sessions.delete(token);return null}
 const requestId=crypto.randomUUID(),digest=await fingerprint(token);let timer;
 const promise=new Promise(resolve=>{pending.set(requestId,{fingerprint:digest,resolve});timer=setTimeout(()=>resolve(null),4000)});
 const clients=await self.clients.matchAll({type:'window',includeUncontrolled:false});for(const client of clients)if(parentClient(client))client.postMessage({type:'NEED_SESSION',fingerprint:digest,requestId});
 const result=await promise;clearTimeout(timer);pending.delete(requestId);return result;
}
async function authorized(event,url){
 let token=grants.get(event.clientId);
 if(!token&&event.clientId){const client=await self.clients.get(event.clientId);if(client){const u=new URL(client.url);if(within(u)&&u.pathname===BASE.pathname+'guide.html')token=u.searchParams.get('session')}}
 if(!token&&event.request.mode==='navigate'&&url.pathname===BASE.pathname+'guide.html')token=url.searchParams.get('session');
 const session=await recover(token);if(!session)return null;
 if(event.clientId)grants.set(event.clientId,token);if(event.resultingClientId)grants.set(event.resultingClientId,token);
 return{...session,token};
}
const privateHeaders={'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Robots-Tag':'noindex, nofollow, noarchive'};
self.addEventListener('fetch',event=>{
 const url=new URL(event.request.url);if(!within(url))return;
 const name=decodeURIComponent(url.pathname.slice(BASE.pathname.length));
 if(publicFiles.has(name)||name.startsWith('vault/'))return;
 event.respondWith((async()=>{
  const session=await authorized(event,url);if(!session)return new Response('Mot de passe requis.',{status:401,headers:privateHeaders});
  if(name==='guide-session')return Response.json({active:true},{headers:privateHeaders});
  if(name==='guide-logout'&&event.request.method==='POST'){
   sessions.delete(session.token);for(const[id,token]of grants)if(token===session.token)grants.delete(id);
   (await self.clients.get(session.parentId))?.postMessage({type:'LOCK',token:session.token});return new Response(null,{status:303,headers:{...privateHeaders,Location:BASE.href}});
  }
  if(event.request.method!=='GET'&&event.request.method!=='HEAD')return new Response('Méthode non disponible.',{status:405,headers:privateHeaders});
  const item=session.manifest.files[name];if(!item)return new Response('Fichier introuvable.',{status:404,headers:privateHeaders});
  if(!/^vault\/[a-f0-9]{32}\.bin$/.test(item.file))return new Response('Fichier invalide.',{status:500,headers:privateHeaders});
  try{
   const response=await fetch(new URL(item.file,BASE));if(!response.ok)throw Error('download');
   const encrypted=new Uint8Array(await response.arrayBuffer());
   const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:encrypted.slice(0,12),additionalData:new TextEncoder().encode('lofi-guide:file:'+name),tagLength:128},session.key,encrypted.slice(12));
   const headers={...privateHeaders,'Content-Type':item.type,'Content-Length':String(plain.byteLength)};
   if(name==='guide.html')headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";
   return new Response(event.request.method==='HEAD'?null:plain,{status:200,headers});
  }catch{return new Response('Impossible de charger ce fichier. Recharge le guide.',{status:502,headers:privateHeaders})}
 })());
});
