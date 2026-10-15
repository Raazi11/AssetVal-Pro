import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import { Pool } from 'pg';
import { z } from 'zod';
import crypto from 'node:crypto';

const app=Fastify({logger:true});
await app.register(helmet);
await app.register(cors,{origin:false});
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const auditSchema=z.object({orgId:z.string().uuid(),actorId:z.string().uuid().nullable(),action:z.string().min(1),entity:z.string().min(1),entityId:z.string().min(1),metadata:z.record(z.any()).default({})});

async function audit(input:z.infer<typeof auditSchema>){
  const x=auditSchema.parse(input);
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const prev=await client.query('SELECT hash FROM audit_events WHERE org_id=$1 ORDER BY sequence DESC LIMIT 1 FOR UPDATE',[x.orgId]);
    const previousHash=prev.rows[0]?.hash??'GENESIS';
    const payload=JSON.stringify({...x,previousHash});
    const hash=crypto.createHash('sha256').update(payload).digest('hex');
    await client.query('INSERT INTO audit_events(org_id,actor_id,action,entity,entity_id,metadata,previous_hash,hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[x.orgId,x.actorId,x.action,x.entity,x.entityId,x.metadata,previousHash,hash]);
    await client.query('COMMIT');
    return hash;
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
app.get('/health',async()=>({ok:true,service:'assetval-pro-api'}));
app.post('/v1/audit',async(req,res)=>{try{return {hash:await audit(req.body as any)}}catch{return res.code(400).send({error:'invalid audit event'})}});
app.listen({host:'0.0.0.0',port:Number(process.env.PORT||8080)});
