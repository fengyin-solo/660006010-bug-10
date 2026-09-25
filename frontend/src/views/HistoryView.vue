<template>
  <div class="history">
    <h2>审计历史</h2>
    <div v-if="loading" class="hint">加载中...</div>
    <div v-else-if="error" class="error-bar">
      <span>{{ error }}</span>
      <button class="btn-sm" @click="load">重试</button>
    </div>
    <div v-else-if="history.length === 0" class="hint">暂无审计记录</div>
    <div v-else class="history-list">
      <div v-for="item in history" :key="item.id" class="history-card">
        <div class="history-main">
          <div class="history-file">{{ item.filename }}</div>
          <div class="history-meta">
            <span class="history-time">{{ item.timestamp }}</span>
            <span class="history-rules">规则 v{{ item.rulesVersion }}</span>
            <span>{{ item.vulnerabilityCount }} 个问题</span>
          </div>
        </div>
        <div class="history-score" :class="scoreClass(item.score)">{{ item.score }}分</div>
        <button class="btn-sm" @click="openDetail(item.id)">查看详情</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import { useRouter } from "vue-router"
import { useAuditStore } from "@/store"

const router = useRouter()
const store = useAuditStore()
const loading = ref(true)
const error = ref("")
const history = ref(store.history)

function scoreClass(score: number) {
  if (score >= 75) return "high"
  if (score >= 60) return "medium"
  return "low"
}

async function load() {
  loading.value = true
  error.value = ""
  try {
    history.value = await store.fetchHistory()
  } catch {
    error.value = "历史记录加载失败"
  } finally {
    loading.value = false
  }
}

function openDetail(id: string) {
  router.push(`/history/${id}`)
}

onMounted(load)
</script>

<style scoped>
.history { max-width: 800px; }
.hint { color: #6b7280; padding: 2rem 0; text-align: center; }
.error-bar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.75rem 1rem; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; color: #b91c1c; }
.history-list { display: flex; flex-direction: column; gap: 1rem; }
.history-card { background: white; border-radius: 12px; padding: 1.25rem; display: flex; align-items: center; gap: 1rem; }
.history-main { flex: 1; }
.history-file { font-weight: 600; }
.history-meta { display: flex; gap: 0.75rem; margin-top: 0.25rem; font-size: 0.75rem; color: #9ca3af; }
.history-score { padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600; font-size: 0.875rem; }
.history-score.high { background: #d1fae5; color: #065f46; }
.history-score.medium { background: #fef3c7; color: #92400e; }
.history-score.low { background: #fee2e2; color: #991b1b; }
.btn-sm { background: #e5e7eb; border: none; padding: 0.25rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
</style>
