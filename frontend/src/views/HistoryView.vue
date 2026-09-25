<template>
  <div class="history">
    <h2>审计历史</h2>
    <div v-if="errorMessage" class="error-banner">
      <span>加载失败：{{ errorMessage }}</span>
      <button class="btn-retry" @click="loadHistory">重试</button>
    </div>
    <div v-else-if="history.length === 0" class="empty-tip">暂无审计记录，请先在「审计」页扫描合约。</div>
    <div class="history-list">
      <div v-for="item in history" :key="item.id" class="history-card">
        <div class="history-main">
          <div class="history-file">{{ item.filename }}</div>
          <div class="history-meta">{{ item.vulnerabilityCount }} 个漏洞 · 评分口径 {{ item.scoringVersion }}</div>
          <div class="history-time">{{ item.timestamp }}</div>
        </div>
        <div class="history-score" :class="item.score >= 80 ? 'high' : item.score >= 50 ? 'medium' : 'low'">{{ item.score }}分</div>
        <button class="btn-sm" @click="toggleDetail(item.id)">
          {{ expandedId === item.id ? "收起" : "查看详情" }}
        </button>
      </div>
    </div>
    <div v-if="detail" class="detail-panel">
      <h3>{{ detail.filename }} — 审计详情</h3>
      <div class="detail-score">评分 {{ detail.score }}（{{ detail.grade }}） · {{ detail.vulnerabilities.length }} 个漏洞</div>
      <div v-for="(v, i) in detail.vulnerabilities" :key="i" class="vuln-card" :class="v.severity">
        <div class="vuln-header">
          <span class="vuln-type">{{ v.type }}</span>
          <span class="vuln-severity">{{ v.severity }}</span>
        </div>
        <div class="vuln-line">第 {{ v.line }} 行</div>
        <pre v-if="v.code" class="vuln-code">{{ v.code }}</pre>
        <div class="vuln-desc">{{ v.description }}</div>
        <div class="vuln-suggest">建议: {{ v.suggestion }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import { storeToRefs } from "pinia"
import { useAuditStore } from "../store"

const store = useAuditStore()
const { history } = storeToRefs(store)
const errorMessage = ref("")
const expandedId = ref("")
const detail = ref<any>(null)

async function loadHistory() {
  errorMessage.value = ""
  try {
    await store.fetchHistory()
  } catch (e: any) {
    errorMessage.value = e?.message || "网络错误"
  }
}

async function toggleDetail(id: string) {
  if (expandedId.value === id) {
    expandedId.value = ""
    detail.value = null
    return
  }
  try {
    detail.value = await store.fetchAuditDetail(id)
    expandedId.value = id
  } catch (e: any) {
    errorMessage.value = e?.message || "网络错误"
  }
}

onMounted(loadHistory)
</script>

<style scoped>
.history { max-width: 800px; }
.error-banner { display: flex; align-items: center; justify-content: space-between; gap: 1rem; background: #fee2e2; color: #991b1b; border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1rem; }
.btn-retry { background: #dc2626; color: white; border: none; padding: 0.375rem 1rem; border-radius: 6px; cursor: pointer; }
.empty-tip { color: #6b7280; padding: 2rem 0; }
.history-list { display: flex; flex-direction: column; gap: 1rem; }
.history-card { background: white; border-radius: 12px; padding: 1.25rem; display: flex; align-items: center; gap: 1rem; }
.history-main { flex: 1; }
.history-file { font-weight: 600; }
.history-meta { color: #6b7280; font-size: 0.75rem; margin-top: 0.25rem; }
.history-time { color: #9ca3af; font-size: 0.75rem; margin-top: 0.125rem; }
.history-score { padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600; font-size: 0.875rem; }
.history-score.high { background: #d1fae5; color: #065f46; }
.history-score.medium { background: #fef3c7; color: #92400e; }
.history-score.low { background: #fee2e2; color: #991b1b; }
.btn-sm { background: #e5e7eb; border: none; padding: 0.25rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
.detail-panel { margin-top: 1.5rem; background: white; border-radius: 12px; padding: 1.5rem; }
.detail-panel h3 { margin-bottom: 0.5rem; }
.detail-score { color: #6b7280; font-size: 0.875rem; margin-bottom: 1rem; }
.vuln-card { background: #f9fafb; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; border-left: 4px solid; }
.vuln-card.critical { border-color: #dc2626; }
.vuln-card.high { border-color: #f59e0b; }
.vuln-card.medium { border-color: #3b82f6; }
.vuln-card.low { border-color: #6b7280; }
.vuln-header { display: flex; justify-content: space-between; margin-bottom: 0.5rem; }
.vuln-type { font-weight: 600; }
.vuln-severity { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; background: #fee2e2; color: #dc2626; }
.vuln-line { font-size: 0.75rem; color: #7c3aed; margin-bottom: 0.5rem; font-family: monospace; }
.vuln-code { background: #1e1e1e; color: #d4d4d4; font-family: "Fira Code", monospace; font-size: 0.75rem; padding: 0.75rem; border-radius: 6px; overflow-x: auto; margin-bottom: 0.75rem; }
.vuln-desc { color: #374151; margin-bottom: 0.5rem; }
.vuln-suggest { font-size: 0.875rem; color: #6b7280; }
</style>
