const base=new URL('./',location.href),login=document.querySelector('#login'),frame=document.querySelector('#guide'),status=document.querySelector('#status'),button=document.querySelector('#submit');
let session=null,registration=null;
const bytes=b64=>Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
function lock(message=''){
 session=null;frame.hidden=true;frame.removeAttribute('src');login.hidden=false;document.body.classList.remove('open');status.textContent=message;button.disabled=false;document.querySelector('#password').value='';
}
async function worker(){
 if(!('serviceWorker' in navigator)||!crypto.subtle)throw Error('Ouvre le guide dans un navigateur récent, en HTTPS.');
 registration??=await navigator.serviceWorker.register(new URL('sw.js',base),{scope:base.pathname});
 await navigator.serviceWorker.ready;
 if(!navigator.serviceWorker.controller)await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>reject(Error('Recharge cette page pour ouvrir le guide.')),15000);navigator.serviceWorker.addEventListener('controllerchange',()=>{clearTimeout(timeout);resolve()},{once:true})});
 return navigator.serviceWorker.controller;
}
async function send(message){
 const controller=await worker();const channel=new MessageChannel();
 const response=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('La connexion au guide a expiré. Réessaie.')),15000);channel.port1.onmessage=e=>{clearTimeout(timer);channel.port1.close();e.data?.ok?resolve(e.data):reject(Error('Impossible d’ouvrir le guide.'))}});
 controller.postMessage(message,[channel.port2]);return response;
}
navigator.serviceWorker?.addEventListener('message',event=>{
 if(event.source!==navigator.serviceWorker.controller)return;
 const data=event.data;
 if(data?.type==='NEED_SESSION'&&session&&data.fingerprint===session.fingerprint)event.source.postMessage({type:'RESTORE_SESSION',requestId:data.requestId,...session});
 if(data?.type==='LOCK'&&session&&data.token===session.token)lock('Session fermée.');
});
window.addEventListener('message',event=>{
 if(event.origin!==location.origin||event.source!==frame.contentWindow)return;
 if(event.data?.type==='GUIDE_ROUTE'&&typeof event.data.hash==='string'&&/^#[a-z/-]*$/.test(event.data.hash))history.replaceState(null,'',base.pathname+event.data.hash);
});
document.querySelector('#form').addEventListener('submit',async event=>{
 event.preventDefault();button.disabled=true;status.textContent='Ouverture du guide…';
 let password=document.querySelector('#password').value;
 try{
  const config=await fetch(new URL('boot.json',base),{cache:'no-store'}).then(r=>{if(!r.ok)throw Error();return r.json()});
  if(config.schema!==1||config.iterations!==600000)throw Error('Version du guide non reconnue.');
  const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);password='';
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:bytes(config.salt),iterations:config.iterations},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const encrypted=new Uint8Array(await fetch(new URL(config.manifest,base)).then(r=>{if(!r.ok)throw Error();return r.arrayBuffer()}));
  let manifest;try{manifest=JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:encrypted.slice(0,12),additionalData:new TextEncoder().encode('lofi-guide:manifest:v1'),tagLength:128},key,encrypted.slice(12))))}catch{throw Error('Mot de passe incorrect.')}
  if(manifest.schema!==1||!manifest.files?.['guide.html'])throw Error('Le guide est incomplet.');
  const token=Array.from(crypto.getRandomValues(new Uint8Array(24)),n=>n.toString(16).padStart(2,'0')).join('');
  const fingerprint=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token))),n=>n.toString(16).padStart(2,'0')).join('');
  session={token,key,manifest,fingerprint};await send({type:'UNLOCK',...session});
  document.querySelector('#password').value='';login.hidden=true;frame.hidden=false;document.body.classList.add('open');
  const target=new URL('guide.html',base);target.searchParams.set('session',token);target.hash=location.hash;frame.src=target.href;status.textContent='';
 }catch(error){session=null;status.textContent=error.message||'Impossible d’ouvrir le guide. Réessaie.';button.disabled=false}
});
worker().catch(error=>{status.textContent=error.message});
