import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import { Pool } from 'pg';
import { z } from 'zod';
import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const app=Fastify({logger:true});
await app.register(helmet);
await app.register(cors,{origin:false});
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const OIDC_ISSUER=process.env.OIDC_ISSUER?.replace(/\/$/,'');
const OIDC_AUDIENCE=process.env.OIDC_AUDIENCE;
const OIDC_JWKS_URL=process.env.OIDC_JWKS_URL;
const OIDC_REQUIRED=process.env.OIDC_REQUIRED!=='false';
const jwks=OIDC_JWKS_URL?createRemoteJWKSet(new URL(OIDC_JWKS_URL)):null;
type AuthContext={userId:string;orgId:string;role:string;email:string;subject:string};
async function authenticate(req:any,res:any):Promise<AuthContext|null>{
  if(!OIDC_REQUIRED)return null;
  const header=String(req.headers.authorization||'');
  if(!header.startsWith('Bearer ')){res.code(401).send({error:'authentication_required'});return null}
  if(!jwks||!OIDC_ISSUER||!OIDC_AUDIENCE){res.code(500).send({error:'oidc_not_configured'});return null}
  try{
    const {payload}=await jwtVerify(header.slice(7),jwks,{issuer:OIDC_ISSUER,audience:OIDC_AUDIENCE});
    const subject=String(payload.sub||''),email=String(payload.email||payload.preferred_username||'').toLowerCase();
    const orgId=String(req.body?.orgId||req.query?.orgId||'');
    if(!subject||!z.string().uuid().safeParse(orgId).success){res.code(400).send({error:'valid orgId is required'});return null}
    const q=await pool.query(`SELECT u.id AS "userId",u.email,m.org_id AS "orgId",m.role,u.oidc_subject AS "oidcSubject" FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.org_id=$1 AND (u.oidc_subject=$2 OR lower(u.email)=lower($3)) LIMIT 1`,[orgId,subject,email]);
    if(!q.rowCount){res.code(403).send({error:'organization_access_denied'});return null}
    const row=q.rows[0];if(!row.oidcSubject)await pool.query('UPDATE users SET oidc_subject=$1 WHERE id=$2',[subject,row.userId]);
    return {userId:row.userId,orgId:row.orgId,role:row.role,email:row.email,subject};
  }catch(e){req.log.warn({err:e},'OIDC verification failed');res.code(401).send({error:'invalid_access_token'});return null}
}
function requireRole(auth:AuthContext|null,roles:string[],res:any){if(!auth){if(!res.sent)res.code(401).send({error:'authentication_required'});return false}if(!roles.includes(auth.role)){res.code(403).send({error:'insufficient_role',requiredRoles:roles});return false}return true}
app.addHook('preHandler',async(req:any,res:any)=>{
  if(req.url.split('?')[0]==='/health')return;
  const auth=await authenticate(req,res);if(res.sent)return;if(auth)req.auth=auth;
});

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
app.get('/v1/auth/me',async(req:any,res)=>{const auth=req.auth as AuthContext|undefined;if(!auth)return res.code(401).send({error:'authentication_required'});return auth;});
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
  orgId:z.string().uuid(),tag:z.string().min(1).max(80).optional(),assetName:z.string().min(1).max(200),serial:z.string().max(160).nullable().default(null),
  categoryId:z.string().uuid().nullable().default(null),brand:z.string().max(120).nullable().default(null),locationId:z.string().uuid().nullable().default(null),departmentId:z.string().uuid().nullable().default(null),custodianId:z.string().uuid().nullable().default(null),
  vendorId:z.string().uuid().nullable().default(null),model:z.string().max(160).nullable().default(null),condition:z.enum(['Excellent','Good','Fair','Poor','Damaged']).default('Good'),cost:z.coerce.number().nonnegative().default(0),
  usefulLifeYears:z.coerce.number().positive().default(5),salvageValue:z.coerce.number().nonnegative().default(0),
  depreciationMethod:z.enum(['straight_line','declining_balance','sum_of_years_digits']).default('straight_line'),purchaseDate:z.string().nullable().default(null),status:z.string().default('Active')
});
app.get('/v1/assets',async(req,res)=>{
  const q=req.query as {orgId?:string;search?:string;categoryId?:string;locationId?:string;departmentId?:string;custodianId?:string;vendorId?:string;status?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success)return res.code(400).send({error:'orgId must be a UUID'});
  const uuid=(v?:string)=>v&&z.string().uuid().safeParse(v).success?v:null;
  try{
    const r=await pool.query(`
      WITH RECURSIVE loc_tree AS (
        SELECT id,org_id,parent_id,location_type,id AS department_id FROM locations WHERE org_id=$1 AND location_type='department'
        UNION ALL
        SELECT l.id,l.org_id,l.parent_id,l.location_type,t.department_id FROM locations l JOIN loc_tree t ON l.parent_id=t.id WHERE l.org_id=$1
      )
      SELECT a.id,a.tag,a.asset_name AS "assetName",a.serial,a.category_id AS "categoryId",c.name AS "categoryName",c.parent_id AS "categoryParentId",
        a.location_id AS "locationId",l.name AS "locationName",lt.department_id AS "departmentId",dep.name AS "departmentName",
        a.custodian_id AS "custodianId",cu.name AS "custodianName",a.vendor_id AS "vendorId",v.name AS "vendorName",
        a.brand,a.model,a.cost,a.condition,a.useful_life_years AS "usefulLifeYears",a.salvage_value AS "salvageValue",
        a.depreciation_method AS "depreciationMethod",a.purchase_date AS "purchaseDate",a.status,a.created_at AS "createdAt"
      FROM assets a
      LEFT JOIN asset_categories c ON c.id=a.category_id
      LEFT JOIN locations l ON l.id=a.location_id
      LEFT JOIN loc_tree lt ON lt.id=a.location_id
      LEFT JOIN locations dep ON dep.id=COALESCE(a.department_id,lt.department_id)
      LEFT JOIN custodians cu ON cu.id=a.custodian_id
      LEFT JOIN vendors v ON v.id=a.vendor_id
      WHERE a.org_id=$1
        AND ($2::text IS NULL OR a.tag ILIKE '%'||$2||'%' OR a.asset_name ILIKE '%'||$2||'%' OR COALESCE(a.serial,'') ILIKE '%'||$2||'%' OR COALESCE(a.brand,'') ILIKE '%'||$2||'%' OR COALESCE(a.model,'') ILIKE '%'||$2||'%')
        AND ($3::uuid IS NULL OR a.category_id=$3)
        AND ($4::uuid IS NULL OR a.location_id=$4)
        AND ($5::uuid IS NULL OR COALESCE(a.department_id,lt.department_id)=$5)
        AND ($6::uuid IS NULL OR a.custodian_id=$6)
        AND ($7::uuid IS NULL OR a.vendor_id=$7)
        AND ($8::text IS NULL OR a.status=$8)
      ORDER BY lower(a.asset_name),a.tag`,[q.orgId,q.search?.trim()||null,uuid(q.categoryId),uuid(q.locationId),uuid(q.departmentId),uuid(q.custodianId),uuid(q.vendorId),q.status?.trim()||null]);
    return r.rows;
  }catch{return res.code(500).send({error:'asset query failed'})}
});

const assetUpdate=assetInput.partial().omit({orgId:true});
app.patch('/v1/assets/:id',async(req,res)=>{
  const p=req.params as {id:string}; const body=req.body as any;
  if(!z.string().uuid().safeParse(p.id).success || !body?.orgId || !z.string().uuid().safeParse(body.orgId).success)return res.code(400).send({error:'invalid asset or orgId'});
  const parsed=assetUpdate.safeParse(body); if(!parsed.success)return res.code(400).send({error:parsed.error.flatten()});
  const v=parsed.data; const fields:string[]=[]; const values:any[]=[p.id,body.orgId]; let n=3;
  const map:any={tag:'tag',assetName:'asset_name',serial:'serial',categoryId:'category_id',brand:'brand',locationId:'location_id',custodianId:'custodian_id',vendorId:'vendor_id',departmentId:'department_id',model:'model',condition:'condition',cost:'cost',usefulLifeYears:'useful_life_years',salvageValue:'salvage_value',depreciationMethod:'depreciation_method',purchaseDate:'purchase_date',status:'status'};
  for(const [k,val] of Object.entries(v)){if(map[k]){fields.push(`${map[k]}=${n++}`);values.push(val)}}
  if(!fields.length)return res.code(400).send({error:'no changes'});
  try{
    const r=await pool.query(`UPDATE assets SET ${fields.join(',')} WHERE id=$1 AND org_id=$2 RETURNING id,tag,asset_name AS "assetName",serial,category_id AS "categoryId",location_id AS "locationId",department_id AS "departmentId",custodian_id AS "custodianId",vendor_id AS "vendorId",brand,model,cost,condition,useful_life_years AS "usefulLifeYears",salvage_value AS "salvageValue",depreciation_method AS "depreciationMethod",purchase_date AS "purchaseDate",status`,values);
    if(!r.rowCount)return res.code(404).send({error:'asset not found'});
    await audit({orgId:body.orgId,actorId:null,action:'asset.updated',entity:'asset',entityId:p.id,metadata:{changes:v}});
    return r.rows[0];
  }catch{return res.code(409).send({error:'asset update failed; check references and unique tag'})}
});

function depreciationSnapshot(cost:number,salvage:number,life:number,purchaseDate:string|null,method:string){
  const today=new Date(); const start=purchaseDate?new Date(purchaseDate):today;
  const years=Math.max(0,Math.min(life,(today.getTime()-start.getTime())/(365.25*24*3600*1000)));
  const depreciable=Math.max(0,cost-salvage); let dep=0;
  if(method==='declining_balance'){const rate=life>0?2/life:0; dep=cost*(1-Math.pow(Math.max(0,1-rate),years));}
  else if(method==='sum_of_years_digits'){const full=Math.ceil(years); const total=life*(life+1)/2; for(let y=1;y<=Math.min(full,life);y++) dep+=depreciable*((life-y+1)/total);}
  else dep=depreciable*(life>0?Math.min(years/life,1):0);
  dep=Math.max(0,Math.min(depreciable,dep)); return {yearsElapsed:years,accumulatedDepreciation:dep,bookValue:Math.max(salvage,cost-dep),annualDepreciation:life>0?depreciable/life:0};
}
app.get('/v1/assets/:id/depreciation',async(req,res)=>{
  const p=req.params as {id:string}; const q=req.query as {orgId?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success || !z.string().uuid().safeParse(p.id).success)return res.code(400).send({error:'invalid asset or orgId'});
  try{
    const r=await pool.query(`SELECT id,tag,asset_name AS "assetName",cost,salvage_value AS "salvageValue",useful_life_years AS "usefulLifeYears",depreciation_method AS "depreciationMethod",purchase_date AS "purchaseDate" FROM assets WHERE id=$1 AND org_id=$2`,[p.id,q.orgId]);
    if(!r.rowCount)return res.code(404).send({error:'asset not found'});
    return {...r.rows[0],...depreciationSnapshot(Number(r.rows[0].cost),Number(r.rows[0].salvageValue),Number(r.rows[0].usefulLifeYears),r.rows[0].purchaseDate,r.rows[0].depreciationMethod)};
  }catch{return res.code(500).send({error:'depreciation calculation failed'})}
});
app.get('/v1/assets/:id',async(req,res)=>{
  const p=req.params as {id:string}; const q=req.query as {orgId?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success || !z.string().uuid().safeParse(p.id).success)return res.code(400).send({error:'invalid asset or orgId'});
  try{
    const r=await pool.query(`SELECT a.*,a.asset_name AS "assetName",a.category_id AS "categoryId",c.name AS "categoryName",c.parent_id AS "categoryParentId",
      l.name AS "locationName",cu.name AS "custodianName",v.name AS "vendorName"
      FROM assets a LEFT JOIN asset_categories c ON c.id=a.category_id LEFT JOIN locations l ON l.id=a.location_id
      LEFT JOIN custodians cu ON cu.id=a.custodian_id LEFT JOIN vendors v ON v.id=a.vendor_id
      WHERE a.id=$1 AND a.org_id=$2`,[p.id,q.orgId]);
    if(!r.rowCount)return res.code(404).send({error:'asset not found'}); return r.rows[0];
  }catch{return res.code(500).send({error:'asset query failed'})}
});
app.post('/v1/assets',async(req,res)=>{
  const x=assetInput.safeParse(req.body); if(!x.success)return res.code(400).send({error:x.error.flatten()});
  const v=x.data;
  try{
    const tag=v.tag || (await pool.query(`SELECT 'AST-' || upper(substr(coalesce(c.code,'GEN'),1,8)) || '-' || lpad((COUNT(a.id)+1)::text,5,'0') AS tag FROM asset_categories c LEFT JOIN assets a ON a.category_id=c.id WHERE c.id=$1 GROUP BY c.code`,[v.categoryId])).rows[0]?.tag || 'AST-GEN-00001';
    const r=await pool.query(`INSERT INTO assets(org_id,tag,asset_name,serial,category_id,location_id,department_id,custodian_id,vendor_id,model,cost,useful_life_years,salvage_value,depreciation_method,purchase_date,status)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      RETURNING id,tag,asset_name AS "assetName",category_id AS "categoryId",location_id AS "locationId",custodian_id AS "custodianId",vendor_id AS "vendorId",cost,useful_life_years AS "usefulLifeYears",salvage_value AS "salvageValue",depreciation_method AS "depreciationMethod",purchase_date AS "purchaseDate",status`,
      [v.orgId,tag,v.assetName,v.serial,v.categoryId,v.locationId,v.departmentId,v.custodianId,v.vendorId,v.model,v.cost,v.usefulLifeYears,v.salvageValue,v.depreciationMethod,v.purchaseDate,v.status]);
    await audit({orgId:v.orgId,actorId:null,action:'asset.created',entity:'asset',entityId:r.rows[0].id,metadata:{tag,categoryId:v.categoryId,cost:v.cost}});
    return res.code(201).send(r.rows[0]);
  }catch{return res.code(409).send({error:'asset could not be created; check references and unique tag'})}
});

// Bulk Excel import validation and commit
const bulkRow=z.object({
  rowNumber:z.coerce.number().int().positive(),
  assetId:z.string().trim().max(80).nullable().default(null),
  name:z.string().trim().max(200).nullable().default(null),
  category:z.string().trim().max(160).nullable().default(null),
  brand:z.string().trim().max(120).nullable().default(null),
  model:z.string().trim().max(160).nullable().default(null),
  serial:z.string().trim().max(160).nullable().default(null),
  location:z.string().trim().max(160).nullable().default(null),
  department:z.string().trim().max(160).nullable().default(null),
  purchaseDate:z.string().trim().nullable().default(null),
  cost:z.any().nullable().default(null),
  condition:z.string().trim().nullable().default(null)
});
const bulkRequest=z.object({orgId:z.string().uuid(),rows:z.array(bulkRow).max(10000)});
function parseImportDate(v:any){
  if(v===null||v===undefined||String(v).trim()==='') return null;
  const x=String(v).trim(),m=x.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{4})$/),iso=x.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  const d=iso?new Date(Date.UTC(+iso[1],+iso[2]-1,+iso[3])):m?new Date(Date.UTC(+m[3],+m[2]-1,+m[1])):new Date(x);
  return Number.isNaN(d.getTime())?null:d.toISOString().slice(0,10);
}
function normalizeName(v:any){return String(v??'').trim().toLowerCase().replace(/\s+/g,' ')}
async function validateBulk(orgId:string,rawRows:any[]){
  const parsed=rawRows.map((r,i)=>bulkRow.safeParse({...r,rowNumber:r?.rowNumber??i+2})).map((x,i)=>x.success?x.data:{rowNumber:i+2,assetId:null,name:null,category:null,brand:null,model:null,serial:null,location:null,department:null,purchaseDate:null,cost:null,condition:null,_schemaError:true});
  const [cats,locs]=await Promise.all([
    pool.query(\`SELECT id,name,code,parent_id FROM asset_categories WHERE active=true AND (org_id IS NULL OR org_id=$1)\`,[orgId]),
    pool.query(\`SELECT id,name,location_type,parent_id FROM locations WHERE active=true AND org_id=$1\`,[orgId])
  ]);
  const catMap=new Map(cats.rows.map(x=>[normalizeName(x.name),x]));
  const locMap=new Map(locs.rows.map(x=>[normalizeName(x.name),x]));
  const existingSerials=(await pool.query(\`SELECT serial FROM assets WHERE org_id=$1 AND serial IS NOT NULL AND trim(serial)<>''\`,[orgId])).rows.map(x=>normalizeName(x.serial));
  const seenSerial=new Set<string>(),seenTag=new Set<string>(),results:any[]=[];
  for(const row of parsed){
    const errors:string[]=[];
    if((row as any)._schemaError){errors.push('Invalid row format');results.push({...row,errors,valid:false});continue}
    if(!row.name)errors.push('Missing asset name');
    const cat=catMap.get(normalizeName(row.category)); if(!cat)errors.push('Invalid or missing category');
    const loc=locMap.get(normalizeName(row.location)); if(!loc)errors.push('Invalid or missing location');
    let dep:any=null;
    if(row.department){
      dep=locMap.get(normalizeName(row.department));
      if(!dep || dep.location_type!=='department')errors.push('Invalid department');
      else if(loc && dep.parent_id!==loc.id)errors.push('Department is not under the selected location');
    }
    const date=parseImportDate(row.purchaseDate); if(!date)errors.push('Missing or invalid purchase date');
    const cost=Number(row.cost); if(row.cost===null||row.cost===''||!Number.isFinite(cost)||cost<0)errors.push('Invalid price');
    const condition=['Excellent','Good','Fair','Poor','Damaged'].includes(String(row.condition||'Good'))?String(row.condition||'Good'):'Good';
    const serial=normalizeName(row.serial);
    if(serial){
      if(existingSerials.includes(serial))errors.push('Duplicate serial number already exists');
      if(seenSerial.has(serial))errors.push('Duplicate serial number in import');
      seenSerial.add(serial);
    }
    const tag=String(row.assetId||'').trim();
    if(tag){if(seenTag.has(normalizeName(tag)))errors.push('Duplicate Asset ID in import');seenTag.add(normalizeName(tag));}
    results.push({...row,categoryId:cat?.id??null,locationId:loc?.id??null,departmentId:dep?.id??null,purchaseDate:date,cost:Number.isFinite(cost)?cost:null,condition,errors,valid:errors.length===0});
  }
  return results;
}

// Smart Excel Import Intelligence v1.4: clean -> match -> validate -> approve -> import -> history -> rollback
const smartImport=z.object({orgId:z.string().uuid(),mapping:z.record(z.string()),rows:z.array(z.record(z.any())).max(10000),fileName:z.string().max(255).optional()});
const importApprove=z.object({orgId:z.string().uuid(),actorId:z.string().uuid().nullable().default(null)});
function cleanText(v:any){return String(v??'').replace(/[\\u0000-\\u001F]/g,' ').replace(/\\s+/g,' ').trim()}
function cleanSerial(v:any){return cleanText(v).toUpperCase().replace(/\\s+/g,'')}
function parseImportDate(v:any){
  if(v===null||v===undefined||cleanText(v)==='') return null;
  if(typeof v==='number' && Number.isFinite(v)){const d=new Date(Date.UTC(1899,11,30)+v*86400000);return d.toISOString().slice(0,10)}
  const x=cleanText(v),iso=x.match(/^(\\d{4})[-/.](\\d{1,2})[-/.](\\d{1,2})$/),dmy=x.match(/^(\\d{1,2})[\\/\\-.](\\d{1,2})[\\/\\-.](\\d{4})$/);
  const d=iso?new Date(Date.UTC(+iso[1],+iso[2]-1,+iso[3])):dmy?new Date(Date.UTC(+dmy[3],+dmy[2]-1,+dmy[1])):new Date(x);
  return Number.isNaN(d.getTime())?null:d.toISOString().slice(0,10);
}
function cleanCost(v:any){if(typeof v==='number')return Number.isFinite(v)?Math.round(v*100)/100:null;const x=cleanText(v).replace(/[,₹$€£]|SAR|AED|INR|USD/gi,'').replace(/[^0-9.-]/g,'');if(!x)return null;const n=Number(x);return Number.isFinite(n)?Math.round(n*100)/100:null}
function similarity(a:string,b:string){a=normalizeName(a);b=normalizeName(b);if(!a||!b)return 0;if(a===b)return 1;const m=a.length,n=b.length,dp=Array.from({length:m+1},()=>Array(n+1).fill(0));for(let i=0;i<=m;i++)dp[i][0]=i;for(let j=0;j<=n;j++)dp[0][j]=j;for(let i=1;i<=m;i++)for(let j=1;j<=n;j++)dp[i][j]=Math.min(dp[i-1][j]+1,dp[i][j-1]+1,dp[i-1][j-1]+(a[i-1]===b[j-1]?0:1));return 1-dp[m][n]/Math.max(m,n)}
function bestMatch(value:string,items:any[],codeOk=true){const n=normalizeName(value);if(!n)return null;const exact=items.find(x=>normalizeName(x.name)===n||(codeOk&&normalizeName(x.code||'')===n));if(exact)return {...exact,matchType:'exact',matchScore:1};const scored=items.map(x=>({...x,matchScore:Math.max(similarity(n,x.name),codeOk?similarity(n,x.code||''):0)})).sort((a,b)=>b.matchScore-a.matchScore);return scored[0]&&scored[0].matchScore>=0.82?{...scored[0],matchType:'fuzzy'}:null}
function mapSmartRows(body:any){
  return body.rows.map((r:any,i:number)=>({
    rowNumber:i+2,assetId:cleanText(r[body.mapping.assetId]),name:cleanText(r[body.mapping.name]),category:cleanText(r[body.mapping.category]),
    brand:cleanText(r[body.mapping.brand]),model:cleanText(r[body.mapping.model]),serial:cleanSerial(r[body.mapping.serial]),
    location:cleanText(r[body.mapping.location]),department:cleanText(r[body.mapping.department]),purchaseDate:r[body.mapping.purchaseDate]??'',
    cost:r[body.mapping.cost]??'',condition:cleanText(r[body.mapping.condition])||'Good'
  }))
}
async function validateSmart(orgId:string,rawRows:any[]){
  const [cats,locs,existing]=await Promise.all([
    pool.query(`SELECT id,name,code,parent_id FROM asset_categories WHERE active=true AND (org_id IS NULL OR org_id=$1)`,[orgId]),
    pool.query(`SELECT id,name,code,location_type,parent_id FROM locations WHERE active=true AND org_id=$1`,[orgId]),
    pool.query(`SELECT tag,serial FROM assets WHERE org_id=$1`,[orgId])
  ]);
  const catItems=cats.rows,locItems=locs.rows,existingTags=new Set(existing.rows.map(x=>normalizeName(x.tag))),existingSerials=new Set(existing.rows.filter(x=>x.serial).map(x=>normalizeName(x.serial)));
  const seenTags=new Set<string>(),seenSerials=new Set<string>(),results:any[]=[],cleaning={trimmed:0,normalizedSerials:0,normalizedCosts:0,normalizedDates:0},duplicates={existing:0,inFile:0};
  for(const raw of rawRows){
    const errors:string[]=[],warnings:string[]=[];
    const name=cleanText(raw.name),category=bestMatch(raw.category,catItems),location=bestMatch(raw.location,locItems),department=raw.department?bestMatch(raw.department,locItems):null;
    const purchaseDate=parseImportDate(raw.purchaseDate),cost=cleanCost(raw.cost),serial=cleanSerial(raw.serial),tag=cleanText(raw.assetId);
    if(name!==raw.name)cleaning.trimmed++;if(serial!==raw.serial&&serial)cleaning.normalizedSerials++;if(String(cost??'')!==cleanText(raw.cost)&&cost!==null)cleaning.normalizedCosts++;if(purchaseDate&&purchaseDate!==cleanText(raw.purchaseDate))cleaning.normalizedDates++;
    if(!name)errors.push('Missing asset name');
    if(!category)errors.push('Category not matched'); else if(category.matchType==='fuzzy')warnings.push('Category fuzzy-matched to '+category.name);
    if(!location)errors.push('Location not matched'); else if(location.matchType==='fuzzy')warnings.push('Location fuzzy-matched to '+location.name);
    if(raw.department){if(!department||department.location_type!=='department')errors.push('Department not matched');else if(location&&department.parent_id!==location.id)errors.push('Department is not under the selected location');}
    if(!purchaseDate)errors.push('Missing or invalid purchase date');
    if(cost===null||cost<0)errors.push('Invalid price');
    const condition=['Excellent','Good','Fair','Poor','Damaged'].includes(raw.condition)?raw.condition:'Good';
    if(raw.condition&&!['Excellent','Good','Fair','Poor','Damaged'].includes(raw.condition))warnings.push('Condition normalized to Good');
    if(tag){const k=normalizeName(tag);if(existingTags.has(k)){errors.push('Duplicate Asset ID already exists');duplicates.existing++}if(seenTags.has(k)){errors.push('Duplicate Asset ID in import');duplicates.inFile++}seenTags.add(k)}
    if(serial){const k=normalizeName(serial);if(existingSerials.has(k)){errors.push('Duplicate serial number already exists');duplicates.existing++}if(seenSerials.has(k)){errors.push('Duplicate serial number in import');duplicates.inFile++}seenSerials.add(k)}
    results.push({...raw,assetId:tag,name,category:category?.name||raw.category,categoryId:category?.id||null,categoryMatch:category?{type:category.matchType,score:category.matchScore}:null,
      location:location?.name||raw.location,locationId:location?.id||null,locationMatch:location?{type:location.matchType,score:location.matchScore}:null,
      department:department?.name||raw.department,departmentId:department?.id||null,purchaseDate,cost,serial,condition,warnings,errors,valid:errors.length===0});
  }
  return {rows:results,cleaning,duplicates};
}
app.post('/v1/import/smart/validate',async(req,res)=>{
  const body=smartImport.safeParse(req.body);if(!body.success)return res.code(400).send({error:body.error.flatten()});
  try{const mapped=mapSmartRows(body.data),v=await validateSmart(body.data.orgId,mapped);return {fileName:body.data.fileName||null,total:v.rows.length,valid:v.rows.filter(x=>x.valid).length,invalid:v.rows.filter(x=>!x.valid).length,cleaning:v.cleaning,duplicates:v.duplicates,rows:v.rows};}
  catch{return res.code(500).send({error:'smart import validation failed'})}
});
app.post('/v1/import/smart/prepare',async(req,res)=>{
  const body=smartImport.safeParse(req.body);if(!body.success)return res.code(400).send({error:body.error.flatten()});
  const auth=req.auth as AuthContext;if(!requireRole(auth,['owner','admin','asset_manager'],res))return;
  const mapped=mapSmartRows(body.data),v=await validateSmart(body.data.orgId,mapped);if(v.rows.some(x=>!x.valid))return res.code(422).send({error:'Fix validation errors before requesting approval',validation:v});
  const batchId='IMP-'+Date.now()+'-'+Math.random().toString(36).slice(2,8).toUpperCase(),client=await pool.connect();
  try{await client.query('BEGIN');await client.query(`INSERT INTO asset_import_batches(id,org_id,file_name,total_rows,imported_rows,error_rows,status,asset_ids,mapping,cleaning_summary,duplicate_summary) VALUES($1,$2,$3,$4,0,0,'pending_approval','[]'::jsonb,$5::jsonb,$6::jsonb,$7::jsonb)`,
    [batchId,body.data.orgId,body.data.fileName||null,v.rows.length,JSON.stringify(body.data.mapping),JSON.stringify(v.cleaning),JSON.stringify(v.duplicates)]);
    for(const row of v.rows)await client.query(`INSERT INTO asset_import_batch_items(batch_id,row_number,data,errors,action) VALUES($1,$2,$3::jsonb,'[]'::jsonb,'imported')`,[batchId,row.rowNumber,JSON.stringify(row)]);
    const ap=await client.query(`INSERT INTO approvals(org_id,entity,entity_id,status,requested_by,comments) VALUES($1,'asset_import_batch',$2,'pending',$3,$4) RETURNING id`,[body.data.orgId,batchId,req.auth?.userId||null,'Bulk asset import approval request']);
    await client.query('UPDATE asset_import_batches SET approval_id=$1 WHERE id=$2',[ap.rows[0].id,batchId]);await client.query('COMMIT');
    await audit({orgId:body.data.orgId,actorId:(req.auth as AuthContext).userId,action:'asset.import_batch_submitted',entity:'asset_import_batch',entityId:batchId,metadata:{total:v.rows.length,cleaning:v.cleaning,duplicates:v.duplicates}});
    return {batchId,approvalId:ap.rows[0].id,status:'pending_approval',total:v.rows.length};
  }catch(e){await client.query('ROLLBACK');return res.code(409).send({error:e instanceof Error?e.message:'prepare failed'})}finally{client.release()}
});
app.post('/v1/import/smart/approve/:id',async(req,res)=>{
  const p=req.params as {id:string},body=importApprove.safeParse(req.body);if(!body.success)return res.code(400).send({error:body.error.flatten()});
  const auth=req.auth as AuthContext;if(!requireRole(auth,['owner','admin','approver'],res))return;
  body.data.actorId=auth.userId;
  const client=await pool.connect();try{await client.query('BEGIN');const b=await client.query(`SELECT approval_id,status FROM asset_import_batches WHERE id=$1 AND org_id=$2 FOR UPDATE`,[p.id,body.data.orgId]);if(!b.rowCount)return res.code(404).send({error:'batch not found'});if(b.rows[0].status!=='pending_approval')return res.code(409).send({error:'batch is not awaiting approval'});
    await client.query(`UPDATE approvals SET status='approved',reviewed_by=$1,reviewed_at=now() WHERE id=$2`,[body.data.actorId,b.rows[0].approval_id]);await client.query(`UPDATE asset_import_batches SET status='approved',approved_at=now(),approved_by=$1 WHERE id=$2`,[body.data.actorId,p.id]);await client.query('COMMIT');
    await audit({orgId:body.data.orgId,actorId:body.data.actorId,action:'asset.import_batch_approved',entity:'asset_import_batch',entityId:p.id,metadata:{}});return {batchId:p.id,status:'approved'};
  }catch(e){await client.query('ROLLBACK');return res.code(409).send({error:e instanceof Error?e.message:'approval failed'})}finally{client.release()}
});
app.post('/v1/import/smart/import/:id',async(req,res)=>{
  const p=req.params as {id:string},body=importApprove.safeParse(req.body);if(!body.success)return res.code(400).send({error:body.error.flatten()});
  const auth=req.auth as AuthContext;if(!requireRole(auth,['owner','admin','asset_manager'],res))return;
  body.data.actorId=auth.userId;
  const client=await pool.connect();try{await client.query('BEGIN');const b=await client.query(`SELECT status FROM asset_import_batches WHERE id=$1 AND org_id=$2 FOR UPDATE`,[p.id,body.data.orgId]);if(!b.rowCount)return res.code(404).send({error:'batch not found'});if(b.rows[0].status!=='approved')return res.code(409).send({error:'batch must be approved before import'});
    const items=await client.query(`SELECT id,row_number,data FROM asset_import_batch_items WHERE batch_id=$1 ORDER BY row_number`,[p.id]);const assetIds:string[]=[];
    for(const item of items.rows){const row=item.data;let tag=row.assetId||'AST-'+String(Date.now()+assetIds.length).slice(-12);const dup=await client.query(`SELECT 1 FROM assets WHERE org_id=$1 AND (tag=$2 OR (serial IS NOT NULL AND serial=$3)) LIMIT 1`,[body.data.orgId,tag,row.serial||null]);if(dup.rowCount)throw new Error('Duplicate detected during approved import: '+tag);
      const ins=await client.query(`INSERT INTO assets(org_id,tag,asset_name,serial,category_id,location_id,department_id,model,brand,cost,purchase_date,condition,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'Active') RETURNING id`,[body.data.orgId,tag,row.name,row.serial||null,row.categoryId,row.locationId,row.departmentId,row.model||null,row.brand||null,row.cost,row.purchaseDate,row.condition]);
      assetIds.push(ins.rows[0].id);await client.query(`UPDATE asset_import_batch_items SET asset_id=$1,action='imported' WHERE id=$2`,[ins.rows[0].id,item.id]);
      await audit({orgId:body.data.orgId,actorId:body.data.actorId,action:'asset.imported',entity:'asset',entityId:ins.rows[0].id,metadata:{batchId:p.id,rowNumber:item.row_number}});
    }
    await client.query(`UPDATE asset_import_batches SET status='completed',imported_rows=$1,asset_ids=$2::jsonb WHERE id=$3`,[assetIds.length,JSON.stringify(assetIds),p.id]);await client.query('COMMIT');
    await audit({orgId:body.data.orgId,actorId:body.data.actorId,action:'asset.import_batch_completed',entity:'asset_import_batch',entityId:p.id,metadata:{imported:assetIds.length}});return {batchId:p.id,imported:assetIds.length,status:'completed'};
  }catch(e){await client.query('ROLLBACK');return res.code(409).send({error:e instanceof Error?e.message:'import failed'})}finally{client.release()}
});
app.get('/v1/import/history',async(req:any,res)=>{
  const q=req.query as {orgId?:string};if(!q.orgId)return res.code(400).send({error:'orgId required'});
  const auth=req.auth as AuthContext;if(!requireRole(auth,['owner','admin','asset_manager','approver','auditor','viewer'],res))return;
  const r=await pool.query(`SELECT id,file_name AS "fileName",total_rows AS "totalRows",imported_rows AS "importedRows",error_rows AS "errorRows",status,created_at AS "createdAt",rolled_back_at AS "rolledBackAt",cleaning_summary AS "cleaningSummary",duplicate_summary AS "duplicateSummary",approval_id AS "approvalId",approved_at AS "approvedAt" FROM asset_import_batches WHERE org_id=$1 ORDER BY created_at DESC`,[q.orgId]);return r.rows;
});
app.post('/v1/import/history/:id/rollback',async(req,res)=>{
  const p=req.params as {id:string};const q=req.query as {orgId?:string};if(!q.orgId)return res.code(400).send({error:'orgId required'});
  const auth=req.auth as AuthContext;if(!requireRole(auth,['owner','admin'],res))return;
  const client=await pool.connect();try{await client.query('BEGIN');const b=await client.query(`SELECT id,asset_ids,status FROM asset_import_batches WHERE id=$1 AND org_id=$2 FOR UPDATE`,[p.id,q.orgId]);if(!b.rowCount)return res.code(404).send({error:'import batch not found'});if(b.rows[0].status!=='completed')return res.code(409).send({error:'only completed imports can be rolled back'});
    const ids=Array.isArray(b.rows[0].asset_ids)?b.rows[0].asset_ids:JSON.parse(b.rows[0].asset_ids||'[]');const deps=await client.query(`SELECT ((SELECT COUNT(*) FROM asset_transfers t WHERE t.org_id=$1 AND t.asset_id=ANY($2::uuid[])) + (SELECT COUNT(*) FROM service_records s WHERE s.org_id=$1 AND s.asset_id=ANY($2::uuid[])))::int AS n`,[q.orgId,ids]);if(Number(deps.rows[0].n)>0)throw new Error('Rollback blocked: imported assets have dependent service/transfer records');
    await client.query(`DELETE FROM assets WHERE org_id=$1 AND id=ANY($2::uuid[])`,[q.orgId,ids]);await client.query(`UPDATE asset_import_batches SET status='rolled_back',rolled_back_at=now() WHERE id=$1`,[p.id]);await client.query('COMMIT');
    await audit({orgId:q.orgId,actorId:null,action:'asset.import_batch_rolled_back',entity:'asset_import_batch',entityId:p.id,metadata:{deleted:ids.length}});return {rolledBack:true,deleted:ids.length};
  }catch(e){await client.query('ROLLBACK');return res.code(409).send({error:e instanceof Error?e.message:'rollback failed'})}finally{client.release()}
});
app.post('/v1/import/assets/validate',async(req,res)=>{
  const body=bulkRequest.safeParse(req.body); if(!body.success)return res.code(400).send({error:body.error.flatten()});
  try{
    const rows=await validateBulk(body.data.orgId,body.data.rows),valid=rows.filter(x=>x.valid).length;
    return {total:rows.length,valid,invalid:rows.length-valid,summary:{
      purchaseDates:rows.filter(x=>x.errors?.some((e:string)=>e.toLowerCase().includes('purchase date'))).length,
      duplicates:rows.filter(x=>x.errors?.some((e:string)=>e.toLowerCase().includes('duplicate serial'))).length,
      prices:rows.filter(x=>x.errors?.includes('Invalid price')).length
    },rows};
  }catch{return res.code(500).send({error:'bulk import validation failed'})}
});
app.post('/v1/import/assets/commit',async(req,res)=>{
  const body=bulkRequest.safeParse(req.body); if(!body.success)return res.code(400).send({error:body.error.flatten()});
  const rows=await validateBulk(body.data.orgId,body.data.rows);
  if(rows.some(x=>!x.valid))return res.code(422).send({error:'Import contains invalid rows',validation:{total:rows.length,valid:rows.filter(x=>x.valid).length,invalid:rows.filter(x=>!x.valid).length,rows}});
  const client=await pool.connect(); let imported=0;
  try{
    await client.query('BEGIN');
    for(const row of rows){
      let tag=String(row.assetId||'').trim();
      if(!tag){
        const cat=await client.query(\`SELECT 'AST-'||upper(substr(code,1,8))||'-'||lpad((COUNT(*)+1)::text,5,'0') AS tag FROM assets a JOIN asset_categories c ON c.id=a.category_id WHERE a.org_id=$1 AND a.category_id=$2 GROUP BY c.code\`,[body.data.orgId,row.categoryId]);
        tag=cat.rows[0]?.tag||'AST-GEN-'+String(imported+1).padStart(5,'0');
      }
      const exists=await client.query(\`SELECT 1 FROM assets WHERE org_id=$1 AND (tag=$2 OR (serial IS NOT NULL AND serial=$3)) LIMIT 1\`,[body.data.orgId,tag,row.serial||null]);
      if(exists.rowCount)throw new Error('Duplicate Asset ID or serial detected during import: '+tag);
      await client.query(\`INSERT INTO assets(org_id,tag,asset_name,serial,category_id,location_id,department_id,model,brand,cost,purchase_date,condition,status)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'Active')\`,
        [body.data.orgId,tag,row.name,row.serial||null,row.categoryId,row.locationId,row.departmentId,row.model||null,row.brand||null,row.cost,row.purchaseDate,row.condition]);
      imported++;
    }
    await client.query('COMMIT');
    await audit({orgId:body.data.orgId,actorId:null,action:'asset.bulk_imported',entity:'asset_import',entityId:'bulk-'+Date.now(),metadata:{imported}});
    return {imported,skipped:0};
  }catch(e){await client.query('ROLLBACK');return res.code(409).send({error:e instanceof Error?e.message:'bulk import failed'})}finally{client.release()}
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
app.get('/v1/assets/:id/attachments',async(req,res)=>{
  const p=req.params as {id:string}; const q=req.query as {orgId?:string};
  if(!q.orgId || !z.string().uuid().safeParse(q.orgId).success || !z.string().uuid().safeParse(p.id).success)return res.code(400).send({error:'invalid asset or orgId'});
  try{
    const r=await pool.query(`SELECT id,object_key AS "objectKey",content_type AS "contentType",created_at AS "createdAt" FROM attachments WHERE asset_id=$1 AND org_id=$2 ORDER BY created_at DESC`,[p.id,q.orgId]);
    return r.rows;
  }catch{return res.code(500).send({error:'attachment query failed'})}
});
app.listen({host:'0.0.0.0',port:Number(process.env.PORT||8080)});
