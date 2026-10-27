import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createPostgresIdentityRegistry, type PgPool } from '../src/storage/postgres/identity.js';
import { createLifecycleGate } from '../src/core/lifecycle.js';
import { createProviderLifecycle, type ProviderUser, type ProviderOperationStore } from '../src/core/provider-lifecycle.js';
import { createPostgresProviderOperationStore } from '../src/storage/postgres/provider-lifecycle.js';
const databaseUrl = process.env.GATE_TEST_POSTGRES_URL;
test('real PostgreSQL provider lifecycle: generations, supersession, uncertain commits and durable deletion recovery', {
  skip: databaseUrl ? false : 'GATE_TEST_POSTGRES_URL unset; provider operation durability unverified', timeout: 20_000,
}, async t => {
  const url = new URL(databaseUrl!);
  assert.ok(['localhost','127.0.0.1','[::1]'].includes(url.hostname) && ['postgres:','postgresql:'].includes(url.protocol) && !url.search);
  const pgModule = 'pg';
  const { Pool } = await import(pgModule) as { Pool: new (settings: Record<string,unknown>) => PgPool & {end():Promise<void>} };
  const schema = `gate_provider_ops_${process.pid}_${Date.now()}`;
  const settings = {connectionString:databaseUrl,max:8,connectionTimeoutMillis:2000,statement_timeout:3000,query_timeout:4000,lock_timeout:1000};
  const admin=new Pool(settings);const pool=new Pool({...settings,options:`-c search_path=${schema}`});let created=false;
  t.after(async()=>{await pool.end();try{if(created)await admin.query(`DROP SCHEMA ${schema} CASCADE`);}finally{await admin.end();}});
  await admin.query(`CREATE SCHEMA ${schema}`);created=true;
  for(const file of ['001_identity.sql','002_lifecycle.sql','004_provider_operations.sql','005_tenant_policy.sql'])await pool.query(await readFile(`migrations/${file}`,'utf8'));
  const registry=createPostgresIdentityRegistry(pool,{schema});
  const engine=createLifecycleGate({registry,screening:{async screen(){return {allowed:true,reason:'not_listed'};}}});
  const operations=createPostgresProviderOperationStore(pool,{schema});
  const profiles=new Map<string,ProviderUser>();
  const options={tenantId:'t',namespace:'provider.example.test',engine,operations,
    async getUserById(id:string){return profiles.get(id)??null;},
    async deleteUser(id:string,generation:string){assert.equal(profiles.get(id)?.generation,generation);profiles.delete(id);}};
  const coordinator=createProviderLifecycle(options);
  async function owner(id:string,email:string){const row={id,email,emailVerified:true,generation:`created-${id}`};profiles.set(id,row);await engine.claimVerified({tenantId:'t',userId:id,email});return row;}
  await t.test('pending change preserves old ownership; exact current verified target completes and retries once',async()=>{
    const user=await owner('first','Old+Exact@Example.test');
    const begin=await coordinator.beginEmailChange({userId:user.id,email:'New+Exact@Example.test'});
    await coordinator.assertActive({userId:user.id});
    await assert.rejects(coordinator.completeEmailChange({userId:user.id,operationId:begin.operationId}),{code:'ownership_required'});
    profiles.set(user.id,{...user,email:'New+Exact@Example.test',emailVerified:false});
    await assert.rejects(coordinator.completeEmailChange({userId:user.id,operationId:begin.operationId}),{code:'ownership_required'});
    profiles.set(user.id,{...user,email:'New+Exact@Example.test'});
    await coordinator.completeEmailChange({userId:user.id,operationId:begin.operationId});
    await coordinator.completeEmailChange({userId:user.id,operationId:begin.operationId});
    const state=await engine.getOwnership({tenantId:'t',userId:user.id});assert.equal(state.status,'active');
    if(state.status==='active'){assert.equal(state.revision,'2');assert.equal(state.canonical,'New+Exact@example.test');}
  });
  await t.test('same-canonical verified delivery changes advance revision and finish once',async()=>{
    const user=await owner('alias-change','name.one+old@gmail.com');
    const next='na.me.one+new@googlemail.com';
    await coordinator.beginEmailChange({userId:user.id,email:next});
    profiles.set(user.id,{...user,email:next});
    assert.equal(await coordinator.completePendingEmailChange({userId:user.id,email:next}),true);
    assert.equal(await coordinator.completePendingEmailChange({userId:user.id,email:next}),false);
    const state=await engine.getOwnership({tenantId:'t',userId:user.id});
    if(state.status==='active'){assert.equal(state.revision,'2');assert.equal(state.canonical,'nameone@gmail.com');}else assert.fail();
  });
  await t.test('new intent supersedes an old proof and subject generation changes cannot complete',async()=>{
    const user=await owner('superseded','start@example.test');
    const old=await coordinator.beginEmailChange({userId:user.id,email:'old-target@example.test'});
    const next=await coordinator.beginEmailChange({userId:user.id,email:'new-target@example.test'});
    profiles.set(user.id,{...user,email:'old-target@example.test'});
    await assert.rejects(coordinator.completeEmailChange({userId:user.id,operationId:old.operationId}),{code:'stale_revision'});
    profiles.set(user.id,{...user,email:'new-target@example.test',generation:'replacement-user'});
    await assert.rejects(coordinator.completeEmailChange({userId:user.id,operationId:next.operationId}),{code:'ownership_required'});
    profiles.set(user.id,{...user,email:'new-target@example.test'});
    assert.equal(await coordinator.completePendingEmailChange({userId:user.id,email:'old-target@example.test'}),false);
    assert.equal(await coordinator.completePendingEmailChange({userId:user.id,email:'new-target@example.test'}),true);
  });
  await t.test('conflicting target leaves old Gate claim intact and provider-first mismatch denied',async()=>{
    const user=await owner('conflict','conflict-old@example.test');await owner('occupied','occupied@example.test');
    const begin=await coordinator.beginEmailChange({userId:user.id,email:'occupied@example.test'});
    profiles.set(user.id,{...user,email:'occupied@example.test'});
    await assert.rejects(coordinator.completeEmailChange({userId:user.id,operationId:begin.operationId}),{code:'identity_conflict'});
    assert.equal(await registry.owns({tenantId:'t',userId:user.id,canonical:user.email}),true);
    await assert.rejects(coordinator.assertActive({userId:user.id}),{code:'ownership_required'});
  });
  await t.test('metadata transaction failure after Gate CAS leaves a resumable original intent',async()=>{
    const user=await owner('uncertain','uncertain-old@example.test');
    const begin=await coordinator.beginEmailChange({userId:user.id,email:'uncertain-new@example.test'});
    profiles.set(user.id,{...user,email:'uncertain-new@example.test'});
    const failing:ProviderOperationStore={withUserLock:(scope,work)=>operations.withUserLock(scope,tx=>work({...tx,async write(op){await tx.write(op);if(op.status==='complete')throw new Error('synthetic storage loss');}}))};
    const broken=createProviderLifecycle({...options,operations:failing});
    await assert.rejects(broken.completeEmailChange({userId:user.id,operationId:begin.operationId}),{code:'storage_unavailable'});
    await coordinator.completeEmailChange({userId:user.id,operationId:begin.operationId});
    const state=await engine.getOwnership({tenantId:'t',userId:user.id});if(state.status==='active')assert.equal(state.revision,'2');else assert.fail();
  });
  await t.test('unverified pending accounts can be deleted; maintenance preserves deletion intents',async()=>{
    profiles.set('pending',{id:'pending',email:'pending@example.test',emailVerified:false,generation:'pending-generation'});
    await coordinator.deleteAccount({userId:'pending'});
    assert.equal(profiles.has('pending'),false);
    assert.deepEqual(await engine.getOwnership({tenantId:'t',userId:'pending'}),{status:'revoked'});
    await pool.query("UPDATE irondome_gate_provider_operation SET expires_at=CURRENT_TIMESTAMP - interval '1 second'");
    await operations.deleteExpiredChanges();
    const rows=await pool.query("SELECT kind FROM irondome_gate_provider_operation WHERE user_id='pending'");
    assert.equal(rows.rows[0]?.kind,'delete');
  });
  await t.test('deletion intent survives provider failure; revoked IDs cannot change or silently delete a replacement',async()=>{
    const user=await owner('deletion','deletion@example.test');
    const broken=createProviderLifecycle({...options,async deleteUser(){throw new Error('synthetic credential/email error');}});
    await assert.rejects(broken.deleteAccount({userId:user.id}),error=>{assert.equal((error as {code:string}).code,'storage_unavailable');assert.doesNotMatch(String(error),/credential|email/);return true;});
    assert.deepEqual(await engine.getOwnership({tenantId:'t',userId:user.id}),{status:'revoked'});
    profiles.set(user.id,{...user,generation:'replacement-user'});
    await assert.rejects(coordinator.resumeDeletion({userId:user.id}),{code:'identity_revoked'});
    assert.equal(profiles.has(user.id),true);
    profiles.set(user.id,user);await coordinator.resumeDeletion({userId:user.id});await coordinator.resumeDeletion({userId:user.id});
    assert.equal(profiles.has(user.id),false);
    await assert.rejects(coordinator.beginEmailChange({userId:user.id,email:'other@example.test'}),{code:'identity_revoked'});
    const record=await pool.query('SELECT previous_email,next_email,status FROM irondome_gate_provider_operation WHERE user_id=$1',[user.id]);
    assert.deepEqual(record.rows[0],{previous_email:null,next_email:null,status:'deleted'});
  });
});
