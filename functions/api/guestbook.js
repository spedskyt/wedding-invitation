const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers});
const validPassword=p=>typeof p==='string'&&/^\d{4,8}$/.test(p);
const encode=bytes=>Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
async function hashPassword(password,salt){
 const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);
 return encode(new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode(salt),iterations:120000,hash:'SHA-256'},key,256)));
}
async function parseBody(request){
 if(!(request.headers.get('content-type')||'').includes('application/json'))throw {status:415,error:'올바르지 않은 요청입니다.'};
 if(Number(request.headers.get('content-length')||0)>4096)throw {status:413,error:'입력 내용이 너무 깁니다.'};
 try{return await request.json();}catch{throw {status:400,error:'입력 내용을 확인해 주세요.'};}
}
async function authorize(env,id,password){
 if(!Number.isSafeInteger(id)||id<1||!validPassword(password))throw {status:400,error:'글 번호와 비밀번호를 확인해 주세요.'};
 const row=await env.DB.prepare('SELECT password_salt,password_hash FROM guestbook WHERE id=?').bind(id).first();
 if(!row)throw {status:404,error:'해당 글을 찾을 수 없습니다.'};
 if(!row.password_salt||!row.password_hash)throw {status:403,error:'기존에 작성된 글은 관리자에게 수정·삭제를 요청해 주세요.'};
 const actual=await hashPassword(password,row.password_salt);
 if(actual!==row.password_hash)throw {status:403,error:'비밀번호가 일치하지 않습니다.'};
}
const fail=e=>reply({error:e?.error||'요청을 처리하지 못했습니다.'},e?.status||500);
export async function onRequestGet({env,request}){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 try{
  const before=new URL(request.url).searchParams.get('before');
  const parsed=before&&/^\d+$/.test(before)?Number(before):null;
  const query=parsed?'SELECT id,name,message,created_at,password_hash IS NOT NULL AS editable FROM guestbook WHERE id < ? ORDER BY id DESC LIMIT 21':'SELECT id,name,message,created_at,password_hash IS NOT NULL AS editable FROM guestbook ORDER BY id DESC LIMIT 21';
  const result=parsed?await env.DB.prepare(query).bind(parsed).all():await env.DB.prepare(query).all();
  const rows=result.results||[];return reply({items:rows.slice(0,20),next_cursor:rows.length>20?String(rows[19].id):null});
 }catch(e){return fail(e);}
}
export async function onRequestPost({env,request}){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 try{
  const body=await parseBody(request);
  if(body.website)return reply({ok:true});
  const name=String(body.name||'').trim(),message=String(body.message||'').trim(),password=body.password;
  if(!name||name.length>30||!message||message.length>500)return reply({error:'이름은 30자, 메시지는 500자 이내로 입력해 주세요.'},400);
  if(!validPassword(password))return reply({error:'비밀번호는 숫자 4~8자리로 입력해 주세요.'},400);
  const ip=request.headers.get('CF-Connecting-IP')||'unknown';
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(ip+':'+new Date().toISOString().slice(0,10)+':'+(env.GUESTBOOK_SALT||'guestbook')));
  const ipHash=encode(new Uint8Array(digest));
  const recent=await env.DB.prepare("SELECT COUNT(*) AS count FROM guestbook WHERE ip_hash = ? AND created_at > datetime('now', '-2 minutes')").bind(ipHash).first();
  if((recent?.count||0)>=2)return reply({error:'잠시 후 다시 등록해 주세요.'},429);
  const salt=encode(crypto.getRandomValues(new Uint8Array(16)));
  const hash=await hashPassword(password,salt);
  await env.DB.prepare('INSERT INTO guestbook (name,message,ip_hash,password_salt,password_hash) VALUES (?,?,?,?,?)').bind(name,message,ipHash,salt,hash).run();
  return reply({ok:true},201);
 }catch(e){return fail(e);}
}
async function modify({env,request},remove){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 try{
  const body=await parseBody(request),id=Number(body.id);
  await authorize(env,id,body.password);
  if(remove){await env.DB.prepare('DELETE FROM guestbook WHERE id=? AND password_hash IS NOT NULL').bind(id).run();}
  else{
   const message=String(body.message||'').trim();
   if(!message||message.length>500)return reply({error:'메시지는 1~500자로 입력해 주세요.'},400);
   await env.DB.prepare('UPDATE guestbook SET message=? WHERE id=? AND password_hash IS NOT NULL').bind(message,id).run();
  }
  return reply({ok:true});
 }catch(e){return fail(e);}
}
export const onRequestPatch=context=>modify(context,false);
export const onRequestDelete=context=>modify(context,true);
