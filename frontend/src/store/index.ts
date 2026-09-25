import { defineStore } from 'pinia'
import { ref } from 'vue'
import axios from 'axios'

export interface SolidityInfo {
  raw: string
  mode: 'checked' | 'legacy' | 'unknown'
  builtin_overflow_checked: boolean
  pragma_present: boolean
  has_safemath: boolean
  summary: string
}

export interface Vulnerability {
  ruleId: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  line: number
  description: string
  suggestion: string
  code: string
  contextStartLine: number
  contextEndLine: number
}

export interface GasIssue {
  functionName: string
  currentGas: number
  optimizedGas: number
  suggestion: string
}

export interface AuditResult {
  id: string
  filename: string
  score: number
  grade: string
  rulesVersion: string
  solidity: SolidityInfo
  vulnerabilities: Vulnerability[]
  gasIssues: GasIssue[]
  timestamp: string
}

export interface AuditSummary {
  id: string
  filename: string
  score: number
  vulnerabilityCount: number
  rulesVersion: string
  timestamp: string
}

interface ApiEnvelope<T> {
  code: number
  message: string
  data: T
}

export class AuditError extends Error {
  retryable: boolean
  constructor(message: string, retryable: boolean) {
    super(message)
    this.retryable = retryable
  }
}

async function postAudit(code: string, filename: string, path: string): Promise<AuditResult> {
  try {
    const res = await axios.post<ApiEnvelope<AuditResult>>(path, { code, filename })
    return res.data.data
  } catch (err: any) {
    const body = err?.response?.data
    if (body && typeof body.message === 'string') {
      throw new AuditError(body.message, !!body.data?.retryable)
    }
    // 网络/超时类失败可以重试
    throw new AuditError('无法连接扫描服务，请稍后重试', true)
  }
}

export const useAuditStore = defineStore('audit', () => {
  const results = ref<AuditResult[]>([])
  const currentResult = ref<AuditResult | null>(null)
  const history = ref<AuditSummary[]>([])
  const patterns = ref<any>(null)

  async function uploadAndAudit(code: string, filename: string) {
    const data = await postAudit(code, filename, '/api/audit')
    currentResult.value = data
    results.value.unshift(data)
    return data
  }

  async function retryAudit(code: string, filename: string) {
    const data = await postAudit(code, filename, '/api/audit/retry')
    currentResult.value = data
    results.value.unshift(data)
    return data
  }

  async function fetchHistory() {
    const res = await axios.get<ApiEnvelope<AuditSummary[]>>('/api/audits')
    history.value = res.data.data
    return history.value
  }

  async function fetchAuditDetail(id: string) {
    const res = await axios.get<ApiEnvelope<AuditResult>>(`/api/audits/${id}`)
    currentResult.value = res.data.data
    return res.data.data
  }

  async function fetchPatterns() {
    const res = await axios.get<ApiEnvelope<any>>('/api/patterns')
    patterns.value = res.data.data
  }

  return {
    results,
    currentResult,
    history,
    patterns,
    uploadAndAudit,
    retryAudit,
    fetchHistory,
    fetchAuditDetail,
    fetchPatterns,
  }
})
