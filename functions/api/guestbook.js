const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers});
export async function onRequestGet({env,request}){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 try{
  const before=new URL(request.url).searchParams.get('before');
  const parsed=before&&/^\\d+$/.test(before)?Number(before):null;
  const query=parsed?'SELECT id,name,message,created_at FROM guestbook WHERE id < ? ORDER BY id DESC LIMIT 21':'SELECT id,name,message,created_at FROM guestbook ORDER BY id DESC LIMIT 21';
  const result=parsed?await env.DB.prepare(query).bind(parsed).all():await env.DB.prepare(query).all();
  const rows=result.results||[];return reply({items:rows.slice(0,20),next_cursor:rows.length>20?String(rows[19].id):null});
 }catch(e){return reply({error:'메시지를 불러올 수 없습니다.'},500);}
}
export async function onRequestPost({env,request}){
 if(!env.DB)return reply({error:'방명록 데이터베이스 연결이 필요합니다.'},503);
 const type=request.headers.get('content-type')||'';if(!type.includes('application/json'))return reply({error:'올바르지 않은 요청입니다.'},415);
 if(Number(request.headers.get('content-length')||0)>4096)return reply({error:'메시지가 너무 깁니다.'},413);
 let body;try{body=await request.json();}catch{return reply({error:'입력 내용을 확인해 주세요.'},400);}
 if(body.website)return reply({ok:true});
 const name=String(body.name||'').trim(),message=String(body.message||'').trim();
 if(!name||name.length>30||!message||message.length>500)return reply({error:'이름은 30자, 메시지는 500자 이내로 입력해 주세요.'},400);
 const ip=request.headers.get('CF-Connecting-IP')||'unknown';
 try{
  const encoder=new TextEncoder();const digest=await crypto.subtle.digest('SHA-256',encoder.encode(ip+':'+new Date().toISOString().slice(0,10)+':'+(env.GUESTBOOK_SALT||'guestbook')));const key=Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,'0')).join('');
  const recent=await env.DB.prepare("SELECT COUNT(*) AS count FROM guestbook WHERE ip_hash = ? AND created_at > datetime('now', '-2 minutes')").bind(key).first();
  if((recent?.count||0)>=2)return reply({error:'잠시 후 다시 등록해 주세요.'},429);
  await env.DB.prepare('INSERT INTO guestbook (name,message,ip_hash) VALUES (?,?,?)').bind(name,message,key).run();return reply({ok:true},201);
 }catch{return reply({error:'메시지를 저장하지 못했습니다.'},500);}
}
