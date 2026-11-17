const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers});
const validPassword=p=>typeof p==='string'&&/^\d{4,8}$/.test(p);
const validId=id=>Number.isSafeInteger(Number(id))&&Number(id)>0&&String(Number(id))===String(id);
async function hashPassword(password,salt){
 const bytes=new TextEncoder().encode(password);
 const key=await crypto.subtle.importKey('raw',bytes,'PBKDF2',false,['deriveBits']);
 const result=await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:120000,hash:'SHA-256'},key,256);
 return Array.from(new Uint8Array(result)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function equalHex(a,b){
 if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;
 let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);return diff===0;
}
async function payload(request){
 if(!(request.headers.get('content-type')||'').includes('application/json'))throw {status:415,message:'올바르지 않은 요청입니다.'};
 if(Number(request.headers.get('content-length')||0)>4096)throw {status:413,message:'요청이 너무 깁니다.'};
 try{return await request.json();}catch{throw {status:400,message:'입력 내용을 확인해 주세요.'};}
}
const fail=e=>reply({error:e.message||'처리 중 오류가 발생했습니다.'},e.status||500);
async function ipKey(request,env){
 const ip=request.headers.get('CF-Connecting-IP')||'unknown';
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(ip+':'+new Date().toISOString().slice(0,10)+':'+(env.GUESTBOOK_SALT||'guestbook')));
 return Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function checkAttempts(env,key){
 const row=await env.DB.prepare("SELECT COUNT(*) AS count FROM guestbook_attempts WHERE ip_hash=? AND created_at > datetime('now','-15 minutes')").bind(key).first();
 if((row?.count||0)>=8)throw {status:429,message:'비밀번호 입력 횟수를 초과했습니다. 15분 후 다시 시도해 주세요.'};
}
async function recordFailure(env,key){
 await env.DB.prepare('INSERT INTO guestbook_attempts(ip_hash) VALUES(?)').bind(key).run();
}
async function authorize(env,request,id,password){
 if(!validId(id)||!validPassword(password))throw {status:400,message:'글 번호 또는 비밀번호를 확인해 주세요.'};
 const key=await ipKey(request,env);
 await checkAttempts(env,key);
 const item=await env.DB.prepare('SELECT id,password_hash,password_salt FROM guestbook WHERE id=?').bind(Number(id)).first();
 if(!item)throw {status:404,message:'해당 글을 찾을 수 없습니다.'};
 if(!item.password_hash||!item.password_salt)throw {status:403,message:'기존에 작성된 글은 비밀번호가 없어 수정·삭제할 수 없습니다.'};
 const hash=await hashPassword(password,item.password_salt);
 if(!equalHex(hash,item.password_hash)){await recordFailure(env,key);throw {status:403,message:'비밀번호가 일치하지 않습니다.'};}
 return Number(id);
}
export async function onRequestGet({env,request}){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 try{
 const before=new URL(request.url).searchParams.get('before');
 const parsed=before&&/^\d+$/.test(before)?Number(before):null;
 const sql=parsed?'SELECT id,name,message,created_at,password_hash IS NOT NULL AS editable FROM guestbook WHERE id < ? ORDER BY id DESC LIMIT 21':'SELECT id,name,message,created_at,password_hash IS NOT NULL AS editable FROM guestbook ORDER BY id DESC LIMIT 21';
 const result=parsed?await env.DB.prepare(sql).bind(parsed).all():await env.DB.prepare(sql).all();
 const rows=result.results||[];
 return reply({items:rows.slice(0,20),next_cursor:rows.length>20?String(rows[19].id):null});
 }catch(e){return reply({error:'메시지를 불러올 수 없습니다. DB 마이그레이션을 확인해 주세요.'},500);}
}
export async function onRequestPost({env,request}){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 try{
 const body=await payload(request);
 if(body.website)return reply({ok:true});
 const name=String(body.name||'').trim(),message=String(body.message||'').trim(),password=body.password;
 if(!name||name.length>30||!message||message.length>500||!validPassword(password))throw {status:400,message:'이름(30자), 메시지(500자), 숫자 비밀번호(4~8자리)를 확인해 주세요.'};
 const key=await ipKey(request,env);
 const recent=await env.DB.prepare("SELECT COUNT(*) AS count FROM guestbook WHERE ip_hash=? AND created_at > datetime('now','-2 minutes')").bind(key).first();
 if((recent?.count||0)>=2)throw {status:429,message:'잠시 후 다시 등록해 주세요.'};
 const salt=crypto.randomUUID();
 const hash=await hashPassword(password,salt);
 await env.DB.prepare('INSERT INTO guestbook(name,message,ip_hash,password_hash,password_salt) VALUES(?,?,?,?,?)').bind(name,message,key,hash,salt).run();
 return reply({ok:true},201);
 }catch(e){return fail(e);}
}
export async function onRequestPatch({env,request}){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 try{
 const body=await payload(request);
 const message=String(body.message||'').trim();
 if(!message||message.length>500)throw {status:400,message:'메시지는 1~500자로 입력해 주세요.'};
 const id=await authorize(env,request,body.id,body.password);
 await env.DB.prepare('UPDATE guestbook SET message=? WHERE id=?').bind(message,id).run();
 return reply({ok:true});
 }catch(e){return fail(e);}
}
export async function onRequestDelete({env,request}){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 try{
 const body=await payload(request);
 const id=await authorize(env,request,body.id,body.password);
 await env.DB.prepare('DELETE FROM guestbook WHERE id=?').bind(id).run();
 return reply({ok:true});
 }catch(e){return fail(e);}
}
