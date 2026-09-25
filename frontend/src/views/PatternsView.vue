<template>
  <div class="patterns">
    <h2>漏洞模式库</h2>
    <div v-if="loading" class="hint">加载中...</div>
    <template v-else-if="data">
      <div class="meta-card">
        <div>规则版本：<b>v{{ data.rulesVersion }}</b></div>
        <div class="meta-block">
          <span class="meta-label">单次扣分：</span>
          <span class="chip critical">critical -{{ data.severityWeights.critical }}</span>
          <span class="chip high">high -{{ data.severityWeights.high }}</span>
          <span class="chip medium">medium -{{ data.severityWeights.medium }}</span>
          <span class="chip low">low -{{ data.severityWeights.low }}</span>
        </div>
        <div class="meta-block">
          <span class="meta-label">等级扣分上限：</span>
          <span class="chip critical">critical {{ data.severityCaps.critical }}</span>
          <span class="chip high">high {{ data.severityCaps.high }}</span>
          <span class="chip medium">medium {{ data.severityCaps.medium }}</span>
          <span class="chip low">low {{ data.severityCaps.low }}</span>
        </div>
        <div class="meta-block">
          <span class="meta-label">评级：</span>
          <span v-for="g in data.scoreGrades" :key="g.grade" class="chip grade">{{ g.grade }} ≥ {{ g.min }}（{{ g.label }}）</span>
        </div>
      </div>
      <div class="pattern-grid">
        <div v-for="p in data.rules" :key="p.id" class="pattern-card">
          <div class="pattern-head">
            <div class="pattern-name">{{ p.type }}</div>
            <div class="pattern-severity" :class="p.severity">{{ p.severity }}</div>
          </div>
          <div class="pattern-desc">{{ p.description }}</div>
          <div class="pattern-rationale"><b>判定标准：</b>{{ p.rationale }}</div>
          <div class="pattern-fix"><b>修复建议：</b>{{ p.suggestion }}</div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue"
import { useAuditStore } from "@/store"

const store = useAuditStore()
const data = ref<any>(null)
const loading = ref(true)

onMounted(async () => {
  try {
    await store.fetchPatterns()
    data.value = store.patterns
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.patterns { max-width: 1000px; }
.hint { color: #6b7280; padding: 2rem 0; text-align: center; }
.meta-card { background: white; border-radius: 12px; padding: 1.25rem; margin-bottom: 1.25rem; font-size: 0.875rem; }
.meta-block { margin-top: 0.625rem; display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
.meta-label { color: #6b7280; }
.chip { padding: 0.125rem 0.625rem; border-radius: 9999px; font-size: 0.75rem; background: #f3f4f6; color: #374151; }
.chip.critical { background: #fee2e2; color: #dc2626; }
.chip.high { background: #fef3c7; color: #d97706; }
.chip.medium { background: #dbeafe; color: #1d4ed8; }
.chip.low { background: #f3f4f6; color: #6b7280; }
.chip.grade { background: #ede9fe; color: #6d28d9; }
.pattern-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
.pattern-card { background: white; border-radius: 12px; padding: 1.25rem; }
.pattern-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
.pattern-name { font-weight: 600; }
.pattern-severity { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; background: #f3f4f6; }
.pattern-severity.critical { background: #fee2e2; color: #dc2626; }
.pattern-severity.high { background: #fef3c7; color: #d97706; }
.pattern-severity.medium { background: #dbeafe; color: #1d4ed8; }
.pattern-desc { color: #374151; font-size: 0.875rem; margin-bottom: 0.625rem; }
.pattern-rationale, .pattern-fix { font-size: 0.8125rem; color: #6b7280; margin-bottom: 0.375rem; line-height: 1.5; }
</style>
