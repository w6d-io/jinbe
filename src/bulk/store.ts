import { getRedisClient } from '../services/redis-client.service.js'
import type { ItemResult, Outcome } from './types.js'

/**
 * Plans and jobs, in Redis: a plan lives an hour (execute it or plan again), a job a day. The job id
 * IS the plan id — one plan runs at most once, so executing it again returns (or resumes) its job.
 * A lease says which replica is running a job; a job whose lease lapsed (the process died) is resumed
 * by the next execute, from the items not yet done.
 */

export const PLAN_TTL_S = 3600
export const JOB_TTL_S = 24 * 3600
export const LEASE_TTL_S = 120

export interface Owner {
  id: string
  clientId: string | null
}

export interface StoredPlan {
  planId: string
  op: string
  owner: Owner
  params: unknown
  items: unknown[]
  outcomes: Outcome[]
  planHash: string
  warnings: string[]
  createdAt: string
  expiresAt: string
}

export type JobItem = { index: number; status: 'pending' | ItemResult['status']; action?: string; reason?: string }

export interface Job {
  id: string
  op: string
  owner: Owner
  planHash: string
  state: 'running' | 'done' | 'failed'
  total: number
  items: JobItem[]
  createdAt: string
  updatedAt: string
  finishedAt?: string
  error?: string
}

const planKey = (id: string) => `jinbe:bulk:plan:${id}`
const jobKey = (id: string) => `jinbe:bulk:job:${id}`
const leaseKey = (id: string) => `jinbe:bulk:lease:${id}`

async function read<T>(key: string): Promise<T | null> {
  const raw = await getRedisClient().get(key)
  return raw ? (JSON.parse(raw) as T) : null
}

export const getPlan = (id: string) => read<StoredPlan>(planKey(id))
export const getJob = (id: string) => read<Job>(jobKey(id))

export async function putPlan(plan: StoredPlan): Promise<void> {
  await getRedisClient().set(planKey(plan.planId), JSON.stringify(plan), 'EX', PLAN_TTL_S)
}

export async function putJob(job: Job): Promise<void> {
  job.updatedAt = new Date().toISOString()
  await getRedisClient().set(jobKey(job.id), JSON.stringify(job), 'EX', JOB_TTL_S)
}

/** Takes the job's lease; false when another runner holds it. */
export async function claimLease(id: string, holder: string): Promise<boolean> {
  return (await getRedisClient().set(leaseKey(id), holder, 'EX', LEASE_TTL_S, 'NX')) === 'OK'
}

export async function renewLease(id: string): Promise<void> {
  await getRedisClient().expire(leaseKey(id), LEASE_TTL_S)
}

export async function releaseLease(id: string): Promise<void> {
  await getRedisClient().del(leaseKey(id))
}
