const BASE=new URL('./',self.location.href),sessions=new Map(),grants=new Map(),pending=new Map();
const publicFiles=new Set(['','index.html','gate.js','gate.css','sw.js','boot.json','favicon.ico','robots.txt','.nojekyll']);
const CIPHER_CACHE='lofi-guide-encrypted-assets-v1',CIPHER_LIMIT=64*1024*1024,CIPHER_COUNT=512;
const PLAIN_LIMIT=32*1024*1024,PLAIN_FILE_LIMIT=8*1024*1024;
const plaintext=new Map(),inflight=new Map(),revoked=new Set();
let plainBytes=0,cipherState=null,cipherQueue=Promise.resolve();
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
const within=url=>url.origin===BASE.origin&&url.pathname.startsWith(BASE.pathname);
const fingerprint=async token=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token))),n=>n.toString(16).padStart(2,'0')).join('');
const parentClient=client=>{if(!client||client.frameType!=='top-level')return false;const u=new URL(client.url);return within(u)&&['','index.html'].includes(u.pathname.slice(BASE.pathname.length))};
const active=session=>session?.active&&sessions.get(session.token)===session;
function validSession(data){return typeof data.token==='string'&&/^[a-f0-9]{48}$/.test(data.token)&&data.key instanceof CryptoKey&&!data.key.extractable&&data.key.algorithm.name==='AES-GCM'&&data.key.usages.length===1&&data.key.usages[0]==='decrypt'&&data.manifest?.schema===1&&data.manifest.files?.['guide.html']}
function forgetSession(session){
 if(!session)return;session.active=false;
 if(sessions.get(session.token)===session)sessions.delete(session.token);
 for(const[id,token]of grants)if(token===session.token)grants.delete(id);
 for(const[key,entry]of plaintext)if(entry.session===session){plaintext.delete(key);plainBytes-=entry.plain.byteLength}
 for(const[key,entry]of inflight)if(entry.session===session)inflight.delete(key);
}
function revokeSession(session){
 forgetSession(session);revoked.add(session.token);
 // Random tokens are never reused; bound tombstones while blocking delayed restore messages.
 while(revoked.size>512)revoked.delete(revoked.values().next().value);
 for(const waiter of pending.values())if(waiter.token===session.token)waiter.resolve(null);
}
function registerSession(data,parentId){
 if(revoked.has(data.token))return null;
 const known=sessions.get(data.token);if(known)return known.parentId===parentId?known:null;
 const session={key:data.key,manifest:data.manifest,parentId,token:data.token,id:crypto.randomUUID(),active:true};
 sessions.set(data.token,session);grants.set(parentId,data.token);return session;
}
self.addEventListener('message',event=>{
 event.waitUntil((async()=>{
  const source=event.source&&await self.clients.get(event.source.id);if(!parentClient(source))return;
  const data=event.data;if(!validSession(data)||revoked.has(data.token))return;
  const existing=sessions.get(data.token);if(existing&&existing.parentId!==source.id)return;
  if(data.type==='UNLOCK'){
   if(registerSession(data,source.id))event.ports[0]?.postMessage({ok:true});
  }else if(data.type==='RESTORE_SESSION'){
   const waiter=pending.get(data.requestId);if(!waiter||waiter.fingerprint!==await fingerprint(data.token)||revoked.has(data.token))return;
   waiter.resolve(registerSession(data,source.id));
  }
 })());
});
async function recover(token){
 if(!/^[a-f0-9]{48}$/.test(token||'')||revoked.has(token))return null;
 const known=sessions.get(token);if(known){if(await self.clients.get(known.parentId))return active(known)?known:null;forgetSession(known);return null}
 const requestId=crypto.randomUUID(),digest=await fingerprint(token);let timer;
 const promise=new Promise(resolve=>{pending.set(requestId,{token,fingerprint:digest,resolve});timer=setTimeout(()=>resolve(null),4000)});
 const clients=await self.clients.matchAll({type:'window',includeUncontrolled:false});for(const client of clients)if(parentClient(client))client.postMessage({type:'NEED_SESSION',fingerprint:digest,requestId});
 const result=await promise;clearTimeout(timer);pending.delete(requestId);return active(result)?result:null;
}
async function authorized(event,url){
 let token=grants.get(event.clientId);
 if(!token&&event.clientId){const client=await self.clients.get(event.clientId);if(client){const u=new URL(client.url);if(within(u)&&u.pathname===BASE.pathname+'guide.html')token=u.searchParams.get('session')}}
 if(!token&&event.request.mode==='navigate'&&url.pathname===BASE.pathname+'guide.html')token=url.searchParams.get('session');
 const session=await recover(token);if(!session)return null;
 if(event.clientId)grants.set(event.clientId,token);if(event.resultingClientId)grants.set(event.resultingClientId,token);
 return session;
}
const privateHeaders={'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Robots-Tag':'noindex, nofollow, noarchive'};
const locked=()=>new Response('Mot de passe requis.',{status:401,headers:privateHeaders});
function rememberPlain(key,session,plain){
 if(!active(session)||plain.byteLength>PLAIN_FILE_LIMIT)return;
 const old=plaintext.get(key);if(old){plaintext.delete(key);plainBytes-=old.plain.byteLength}
 while(plainBytes+plain.byteLength>PLAIN_LIMIT&&plaintext.size){const first=plaintext.keys().next().value;plainBytes-=plaintext.get(first).plain.byteLength;plaintext.delete(first)}
 plaintext.set(key,{session,plain});plainBytes+=plain.byteLength;
}
function cipherOperation(operation){
 const task=cipherQueue.then(operation);cipherQueue=task.catch(()=>{});return task;
}
async function cipherCache(){
 if(!cipherState)cipherState=(async()=>{
  const cache=await caches.open(CIPHER_CACHE),entries=new Map();let size=0;
  const requests=await cache.keys();
  // Read only metadata, in small batches, so a restarted worker does not serialize 512 lookups.
  for(let start=0;start<requests.length;start+=16){
   const metadata=await Promise.all(requests.slice(start,start+16).map(async request=>({request,bytes:Number((await cache.match(request))?.headers.get('Content-Length'))})));
   for(const{request,bytes}of metadata){
    if(!Number.isSafeInteger(bytes)||bytes<28||bytes>CIPHER_LIMIT){await cache.delete(request);continue}
    entries.set(request.url,bytes);size+=bytes;
   }
  }
  const state={cache,entries,size};await trimCipher(state);return state;
 })().catch(error=>{cipherState=null;throw error});
 return cipherState;
}
async function trimCipher(state){
 while(state.size>CIPHER_LIMIT||state.entries.size>CIPHER_COUNT){const url=state.entries.keys().next().value;state.size-=state.entries.get(url);state.entries.delete(url);await state.cache.delete(url)}
}
async function discardCipher(url){
 await cipherOperation(async()=>{const state=await cipherCache();await state.cache.delete(url);state.size-=state.entries.get(url)||0;state.entries.delete(url)}).catch(()=>{});
}
async function rememberCipher(url,encrypted){
 if(encrypted.byteLength>CIPHER_LIMIT)return;
 await cipherOperation(async()=>{
  const state=await cipherCache();
  await state.cache.put(url,new Response(encrypted,{headers:{'Content-Type':'application/octet-stream','Content-Length':String(encrypted.byteLength)}}));
  state.size-=state.entries.get(url)||0;state.entries.delete(url);state.entries.set(url,encrypted.byteLength);state.size+=encrypted.byteLength;await trimCipher(state);
 }).catch(()=>{});
}
async function decryptFile(session,name,encrypted){
 if(encrypted.byteLength<28)throw Error('invalid ciphertext');
 return crypto.subtle.decrypt({name:'AES-GCM',iv:encrypted.slice(0,12),additionalData:new TextEncoder().encode('lofi-guide:file:'+name),tagLength:128},session.key,encrypted.slice(12));
}
async function readFile(session,name,item,bypass){
 const url=new URL(item.file,BASE).href;let corrupt=false;
 if(!bypass){
  let cached;try{cached=await(await cipherCache()).cache.match(url)}catch{}
  if(cached){
   try{
    const plain=await decryptFile(session,name,new Uint8Array(await cached.arrayBuffer()));
    // Only authenticated ciphertext is trusted; this index contains sizes, never plaintext.
    const state=await cipherCache(),size=state.entries.get(url);if(size){state.entries.delete(url);state.entries.set(url,size)}
    return plain;
   }catch{corrupt=true;await discardCipher(url)}
  }
 }
 const response=await fetch(url,{cache:bypass||corrupt?'no-store':'default'});if(!response.ok)throw Error('download');
 const encrypted=new Uint8Array(await response.arrayBuffer()),plain=await decryptFile(session,name,encrypted);
 if(!active(session))throw Error('session ended');
 // CacheStorage receives only the original AES-GCM bytes, after successful verification.
 if(!bypass)await rememberCipher(url,encrypted);
 return plain;
}
async function loadFile(session,name,item,request){
 const bypass=request.cache==='no-store'||request.cache==='reload';
 // The immutable ciphertext filename changes on publication, even for the same logical path.
 const key=session.id+':'+name+':'+item.file;
 if(!bypass){
  const cached=plaintext.get(key);if(cached){plaintext.delete(key);plaintext.set(key,cached);return cached.plain}
  const loading=inflight.get(key);if(loading)return loading.promise;
 }
 const promise=readFile(session,name,item,bypass).then(plain=>{if(!active(session))throw Error('session ended');if(!bypass)rememberPlain(key,session,plain);return plain});
 if(bypass)return promise;
 const entry={session,promise};inflight.set(key,entry);
 try{return await promise}finally{if(inflight.get(key)===entry)inflight.delete(key)}
}
self.addEventListener('fetch',event=>{
 const url=new URL(event.request.url);if(!within(url))return;
 const name=decodeURIComponent(url.pathname.slice(BASE.pathname.length));
 if(publicFiles.has(name)||name.startsWith('vault/'))return;
 event.respondWith((async()=>{
  const session=await authorized(event,url);if(!session)return locked();
  if(name==='guide-session')return Response.json({active:true},{headers:privateHeaders});
  if(name==='guide-logout'&&event.request.method==='POST'){
   revokeSession(session);
   (await self.clients.get(session.parentId))?.postMessage({type:'LOCK',token:session.token});return new Response(null,{status:303,headers:{...privateHeaders,Location:BASE.href}});
  }
  if(event.request.method!=='GET'&&event.request.method!=='HEAD')return new Response('Méthode non disponible.',{status:405,headers:privateHeaders});
  const item=session.manifest.files[name];if(!item)return new Response('Fichier introuvable.',{status:404,headers:privateHeaders});
  if(!/^vault\/[a-f0-9]{32}\.bin$/.test(item.file))return new Response('Fichier invalide.',{status:500,headers:privateHeaders});
  try{
   const plain=await loadFile(session,name,item,event.request);if(!active(session))return locked();
   const headers={...privateHeaders,'Content-Type':item.type,'Content-Length':String(plain.byteLength)};
   if(name==='guide.html')headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";
   return new Response(event.request.method==='HEAD'?null:plain,{status:200,headers});
  }catch{return active(session)?new Response('Impossible de charger ce fichier. Recharge le guide.',{status:502,headers:privateHeaders}):locked()}
 })());
});
