<template>
  <div class="detail">
    <a class="back-link" @click="$router.push('/history')">← 返回历史列表</a>
    <h2>{{ result?.filename || "审计详情" }}</h2>
    <div v-if="loading" class="hint">加载中...</div>
    <div v-else-if="error" class="error-bar">
      <span>{{ error }}</span>
      <button class="btn-sm" @click="load">重试</button>
    </div>
    <AuditResultPanel v-else-if="result" :result="result" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import { useRoute } from "vue-router"
import { useAuditStore, type AuditResult } from "@/store"
import AuditResultPanel from "@/components/AuditResultPanel.vue"

const route = useRoute()
const store = useAuditStore()
const loading = ref(true)
const error = ref("")
const result = ref<AuditResult | null>(null)

async function load() {
  loading.value = true
  error.value = ""
  try {
    result.value = await store.fetchAuditDetail(String(route.params.id))
  } catch {
    error.value = "审计记录加载失败，可能已被删除"
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.detail { max-width: 1000px; }
.back-link { display: inline-block; color: #667eea; cursor: pointer; margin-bottom: 1rem; font-size: 0.875rem; }
.hint { color: #6b7280; padding: 2rem 0; }
.error-bar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.75rem 1rem; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; color: #b91c1c; }
.btn-sm { background: #e5e7eb; border: none; padding: 0.25rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
</style>
