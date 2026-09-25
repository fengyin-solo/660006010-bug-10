<template>
  <div class="patterns">
    <h2>漏洞模式库</h2>
    <div class="pattern-grid">
      <div v-for="p in patterns" :key="p.type" class="pattern-card">
        <div class="pattern-name">{{ p.type }}</div>
        <div class="pattern-severity" :class="p.severity">{{ p.severity }}</div>
        <div class="pattern-desc">{{ p.description }}</div>
        <div class="pattern-suggest">建议: {{ p.suggestion }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from "vue"
import { storeToRefs } from "pinia"
import { useAuditStore } from "../store"

const store = useAuditStore()
const { patterns } = storeToRefs(store)

onMounted(() => { store.fetchPatterns() })
</script>

<style scoped>
.patterns { max-width: 1000px; }
.pattern-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
.pattern-card { background: white; border-radius: 12px; padding: 1.25rem; }
.pattern-name { font-weight: 600; margin-bottom: 0.5rem; }
.pattern-severity { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; margin-bottom: 0.75rem; }
.pattern-severity.critical { background: #fee2e2; color: #dc2626; }
.pattern-severity.high { background: #fef3c7; color: #d97706; }
.pattern-severity.medium { background: #dbeafe; color: #1d4ed8; }
.pattern-desc { color: #6b7280; font-size: 0.875rem; margin-bottom: 0.75rem; }
.pattern-suggest { font-size: 0.75rem; color: #9ca3af; }
</style>
