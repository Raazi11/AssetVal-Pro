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
const locationType=z.enum(['site','building','floor','area','room','department']);
const locationCreate=z.object({orgId:z.string().uuid(),parentId:z.string().uuid().nullable().default(null),locationType,name:z.string().min(1).max(160),code:z.string().max(60).nullable().default(null),address:z.string().max(500).nullable().default(null),description:z.string().max(1000).nullable().default(null)});
const locationUpdate=locationCreate.partial().omit({orgId:true});

app.post('/v1/audit',async(req,res)=>{try{return {hash:await audit(req.body as any)}}catch{return res.code(400).send({error:'invalid audit event'})}});

app.get('/v1/locations',async(req,res)=>{
  const q=req.query as {orgId?:string;parentId?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success) return res.code(400).send({error:'orgId must be a UUID'});
  const params:any[]=[q.orgId];
  let sql=`SELECT l.id,l.org_id AS "orgId",l.parent_id AS "parentId",l.location_type AS "locationType",l.name,l.code,l.address,l.description,l.active,l.created_at AS "createdAt",COUNT(a.id)::int AS "assetCount",COALESCE(SUM(a.cost),0)::numeric AS "assetValue"
    FROM locations l LEFT JOIN assets a ON a.location_id=l.id AND a.org_id=l.org_id
    WHERE l.org_id=$1`;
  if(q.parentId){if(!z.string().uuid().safeParse(q.parentId).success) return res.code(400).send({error:'parentId must be a UUID'});params.push(q.parentId);sql+=` AND l.parent_id=$2`;}
  else sql+=` AND l.parent_id IS NULL`;
  sql+=` GROUP BY l.id ORDER BY lower(l.name)`;
  try{return await pool.query(sql,params).then(r=>r.rows)}catch{return res.code(500).send({error:'location query failed'})}
});

app.get('/v1/locations/:id/assets',async(req,res)=>{
  const p=req.params as {id:string}; const q=req.query as {orgId?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success || !z.string().uuid().safeParse(p.id).success) return res.code(400).send({error:'invalid location or orgId'});
  try{
    const r=await pool.query(`SELECT a.id,a.tag,a.asset_name AS "assetName",a.serial,a.category,a.model,a.cost,a.status,l.name AS "locationName"
      FROM assets a JOIN locations l ON l.id=a.location_id AND l.org_id=a.org_id
      WHERE a.org_id=$1 AND a.location_id=$2 ORDER BY lower(a.asset_name)`,[q.orgId,p.id]);
    return r.rows;
  }catch{return res.code(500).send({error:'asset query failed'})}
});

app.post('/v1/locations',async(req,res)=>{
  const x=locationCreate.safeParse(req.body); if(!x.success)return res.code(400).send({error:x.error.flatten()});
  const v=x.data;
  try{
    const r=await pool.query(`INSERT INTO locations(org_id,parent_id,location_type,name,code,address,description) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,org_id AS "orgId",parent_id AS "parentId",location_type AS "locationType",name,code,address,description,active,created_at AS "createdAt"`,[v.orgId,v.parentId,v.locationType,v.name,v.code,v.address,v.description]);
    await audit({orgId:v.orgId,actorId:null,action:'location.created',entity:'location',entityId:r.rows[0].id,metadata:{name:v.name,locationType:v.locationType,parentId:v.parentId}});
    return res.code(201).send(r.rows[0]);
  }catch(e){return res.code(409).send({error:'location could not be created; check parent and duplicate name'})}
});

app.patch('/v1/locations/:id',async(req,res)=>{
  const p=req.params as {id:string}; if(!z.string().uuid().safeParse(p.id).success)return res.code(400).send({error:'invalid location id'});
  const x=locationUpdate.safeParse(req.body);if(!x.success)return res.code(400).send({error:x.error.flatten()});
  const v=x.data; const fields:string[]=[]; const values:any[]=[p.id,v.orgId??null]; let n=3;
  for(const [k,val] of Object.entries(v)){if(k==='orgId')continue; const col=k.replace(/[A-Z]/g,m=>'_'+m.toLowerCase());fields.push(`${col}=${n++}`);values.push(val);}
  if(!fields.length)return res.code(400).send({error:'no changes'});
  try{
    const r=await pool.query(`UPDATE locations SET ${fields.join(',')} WHERE id=$1 AND org_id=$2 RETURNING id,org_id AS "orgId",parent_id AS "parentId",location_type AS "locationType",name,code,address,description,active,created_at AS "createdAt"`,values);
    if(!r.rowCount)return res.code(404).send({error:'location not found'});
    await audit({orgId:r.rows[0].orgId,actorId:null,action:'location.updated',entity:'location',entityId:p.id,metadata:v});
    return r.rows[0];
  }catch{return res.code(409).send({error:'location update failed'})}
});

app.post('/v1/locations/:id/move-assets',async(req,res)=>{
  const p=req.params as {id:string}; const body=z.object({orgId:z.string().uuid(),assetIds:z.array(z.string().uuid()).min(1),reason:z.string().max(500).nullable().default(null)}).safeParse(req.body);
  if(!body.success || !z.string().uuid().safeParse(p.id).success)return res.code(400).send({error:'invalid request'});
  const v=body.data; const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const loc=await client.query('SELECT id FROM locations WHERE id=$1 AND org_id=$2',[p.id,v.orgId]);
    if(!loc.rowCount)throw new Error('location not found');
    const assets=await client.query('SELECT id,location_id FROM assets WHERE org_id=$1 AND id=ANY($2::uuid[])',[v.orgId,v.assetIds]);
    for(const a of assets.rows){
      await client.query('UPDATE assets SET location_id=$1 WHERE id=$2 AND org_id=$3',[p.id,a.id,v.orgId]);
      await client.query('INSERT INTO asset_transfers(org_id,asset_id,from_location_id,to_location_id,reason,transferred_at) VALUES($1,$2,$3,$4,$5,now())',[v.orgId,a.id,a.location_id,p.id,v.reason]);
    }
    await client.query('COMMIT');
    for(const a of assets.rows) await audit({orgId:v.orgId,actorId:null,action:'asset.location_changed',entity:'asset',entityId:a.id,metadata:{toLocationId:p.id,reason:v.reason}});
    return {moved:assets.rowCount};
  }catch{await client.query('ROLLBACK');return res.code(409).send({error:'assets could not be moved'})}finally{client.release()}
});

// Asset category hierarchy, asset register, and valuation analytics
const categoryInput=z.object({orgId:z.string().uuid().nullable().default(null),parentId:z.string().uuid().nullable().default(null),code:z.string().min(1).max(60),name:z.string().min(1).max(160),description:z.string().max(500).nullable().default(null)});
app.get('/v1/categories',async(req,res)=>{
  const q=req.query as {orgId?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success) return res.code(400).send({error:'orgId must be a UUID'});
  try{
    const r=await pool.query(`SELECT c.id,c.org_id AS "orgId",c.parent_id AS "parentId",c.code,c.name,c.description,c.is_system AS "isSystem",c.active,
      COUNT(a.id)::int AS "assetCount",COALESCE(SUM(a.cost),0)::numeric AS "assetValue"
      FROM asset_categories c
      LEFT JOIN assets a ON a.category_id=c.id AND a.org_id=$1
      WHERE c.active=true AND (c.org_id IS NULL OR c.org_id=$1)
      GROUP BY c.id ORDER BY c.is_system DESC, lower(c.name)`,[q.orgId]);
    return r.rows;
  }catch{return res.code(500).send({error:'category query failed'})}
});
app.post('/v1/categories',async(req,res)=>{
  const x=categoryInput.safeParse(req.body); if(!x.success)return res.code(400).send({error:x.error.flatten()});
  const v=x.data; if(!v.orgId)return res.code(400).send({error:'custom categories require orgId'});
  try{
    const r=await pool.query(`INSERT INTO asset_categories(org_id,parent_id,code,name,description,is_system)
      VALUES($1,$2,$3,$4,$5,false) RETURNING id,org_id AS "orgId",parent_id AS "parentId",code,name,description,is_system AS "isSystem",active`,
      [v.orgId,v.parentId,v.code,v.name,v.description]);
    await audit({orgId:v.orgId,actorId:null,action:'category.created',entity:'asset_category',entityId:r.rows[0].id,metadata:{name:v.name,parentId:v.parentId}});
    return res.code(201).send(r.rows[0]);
  }catch{return res.code(409).send({error:'category could not be created; code may already exist'})}
});
const assetInput=z.object({
  orgId:z.string().uuid(),tag:z.string().min(1).max(80),assetName:z.string().min(1).max(200),serial:z.string().max(160).nullable().default(null),
  categoryId:z.string().uuid().nullable().default(null),locationId:z.string().uuid().nullable().default(null),custodianId:z.string().uuid().nullable().default(null),
  vendorId:z.string().uuid().nullable().default(null),model:z.string().max(160).nullable().default(null),cost:z.coerce.number().nonnegative().default(0),
  usefulLifeYears:z.coerce.number().positive().default(5),salvageValue:z.coerce.number().nonnegative().default(0),
  depreciationMethod:z.enum(['straight_line','declining_balance','sum_of_years_digits']).default('straight_line'),purchaseDate:z.string().nullable().default(null),status:z.string().default('Active')
});
app.get('/v1/assets',async(req,res)=>{
  const q=req.query as {orgId?:string;categoryId?:string;locationId?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success)return res.code(400).send({error:'orgId must be a UUID'});
  try{
    const r=await pool.query(`SELECT a.id,a.tag,a.asset_name AS "assetName",a.serial,a.category_id AS "categoryId",c.name AS "categoryName",
      c.parent_id AS "categoryParentId",a.location_id AS "locationId",l.name AS "locationName",a.custodian_id AS "custodianId",cu.name AS "custodianName",
      a.vendor_id AS "vendorId",v.name AS "vendorName",a.model,a.cost,a.useful_life_years AS "usefulLifeYears",a.salvage_value AS "salvageValue",
      a.depreciation_method AS "depreciationMethod",a.purchase_date AS "purchaseDate",a.status
      FROM assets a LEFT JOIN asset_categories c ON c.id=a.category_id LEFT JOIN locations l ON l.id=a.location_id
      LEFT JOIN custodians cu ON cu.id=a.custodian_id LEFT JOIN vendors v ON v.id=a.vendor_id
      WHERE a.org_id=$1 AND ($2::uuid IS NULL OR a.category_id=$2) AND ($3::uuid IS NULL OR a.location_id=$3)
      ORDER BY lower(a.asset_name)`,[q.orgId,q.categoryId||null,q.locationId||null]);
    return r.rows;
  }catch{return res.code(500).send({error:'asset query failed'})}
});
app.post('/v1/assets',async(req,res)=>{
  const x=assetInput.safeParse(req.body); if(!x.success)return res.code(400).send({error:x.error.flatten()});
  const v=x.data;
  try{
    const r=await pool.query(`INSERT INTO assets(org_id,tag,asset_name,serial,category_id,location_id,custodian_id,vendor_id,model,cost,useful_life_years,salvage_value,depreciation_method,purchase_date,status)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      RETURNING id,tag,asset_name AS "assetName",category_id AS "categoryId",location_id AS "locationId",custodian_id AS "custodianId",vendor_id AS "vendorId",cost,useful_life_years AS "usefulLifeYears",salvage_value AS "salvageValue",depreciation_method AS "depreciationMethod",purchase_date AS "purchaseDate",status`,
      [v.orgId,v.tag,v.assetName,v.serial,v.categoryId,v.locationId,v.custodianId,v.vendorId,v.model,v.cost,v.usefulLifeYears,v.salvageValue,v.depreciationMethod,v.purchaseDate,v.status]);
    await audit({orgId:v.orgId,actorId:null,action:'asset.created',entity:'asset',entityId:r.rows[0].id,metadata:{tag:v.tag,categoryId:v.categoryId,cost:v.cost}});
    return res.code(201).send(r.rows[0]);
  }catch{return res.code(409).send({error:'asset could not be created; check references and unique tag'})}
});
app.get('/v1/dashboard/valuation',async(req,res)=>{
  const q=req.query as {orgId?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success)return res.code(400).send({error:'orgId must be a UUID'});
  try{
    const rows=await pool.query(`WITH top AS (
      SELECT c.id,c.name,c.code FROM asset_categories c WHERE c.org_id IS NULL AND c.parent_id IS NULL
    ), vals AS (
      SELECT top.id,top.name,top.code,COUNT(a.id)::int AS assets,COALESCE(SUM(a.cost),0)::numeric AS acquisition_value,
      COALESCE(SUM(GREATEST(a.cost-CASE WHEN a.depreciation_method='straight_line'
        THEN GREATEST(a.cost-a.salvage_value,0)*LEAST(GREATEST(EXTRACT(YEAR FROM age(current_date,a.purchase_date)),0)/NULLIF(a.useful_life_years,0),1)
        ELSE 0 END,0)),0)::numeric AS book_value
      FROM top LEFT JOIN asset_categories c2 ON c2.id=top.id OR c2.parent_id=top.id
      LEFT JOIN assets a ON a.category_id=c2.id AND a.org_id=$1
      GROUP BY top.id,top.name,top.code
    ) SELECT * FROM vals ORDER BY acquisition_value DESC`,[q.orgId]);
    const total=await pool.query(`SELECT COUNT(*)::int AS assets,COALESCE(SUM(cost),0)::numeric AS "acquisitionValue" FROM assets WHERE org_id=$1`,[q.orgId]);
    return {currency:'SAR',categories:rows.rows,total:total.rows[0]};
  }catch{return res.code(500).send({error:'valuation dashboard failed'})}
});
app.listen({host:'0.0.0.0',port:Number(process.env.PORT||8080)});
