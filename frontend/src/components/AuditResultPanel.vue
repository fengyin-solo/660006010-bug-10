<template>
  <div class="result-section">
    <div class="score-card" :class="scoreClass">
      <div class="score-label">安全评分（规则版本 {{ result.rulesVersion }}）</div>
      <div class="score-value">{{ result.score }}</div>
      <div class="score-grade">{{ result.grade }}</div>
      <div class="score-thresholds">评级阈值：Excellent ≥90 · Good ≥75 · Fair ≥60 · Poor &lt;60</div>
    </div>

    <div v-if="result.solidity" class="version-card">
      <div class="version-title">版本判定</div>
      <div class="version-summary">{{ result.solidity.summary }}</div>
    </div>

    <div class="vulnerabilities">
      <h3>发现漏洞 ({{ result.vulnerabilities.length }})</h3>
      <div v-for="v in result.vulnerabilities" :key="v.ruleId + '-' + v.line" class="vuln-card" :class="v.severity">
        <div class="vuln-header">
          <span class="vuln-type">{{ v.type }}</span>
          <span class="vuln-severity">{{ severityText(v.severity) }}</span>
        </div>
        <div class="vuln-desc">{{ v.description }}</div>
        <div class="vuln-line">第 {{ v.contextStartLine }}–{{ v.contextEndLine }} 行（命中第 {{ v.line }} 行）</div>
        <pre class="vuln-code"><code>{{ v.code }}</code></pre>
        <div class="vuln-suggest">建议：{{ v.suggestion }}</div>
      </div>
    </div>

    <div v-if="result.gasIssues.length > 0" class="gas-section">
      <h3>Gas 优化建议</h3>
      <div v-for="g in result.gasIssues" :key="g.functionName" class="gas-card">
        <div class="gas-fn">{{ g.functionName }}</div>
        <div class="gas-info">
          当前估算：{{ g.currentGas }} → 优化后：{{ g.optimizedGas }}
          （{{ gasSaving(g) }}% 节省）
        </div>
        <div class="gas-suggest">{{ g.suggestion }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue"
import type { AuditResult, GasIssue } from "@/store"

const props = defineProps<{ result: AuditResult }>()

const scoreClass = computed(() => {
  if (props.result.score >= 75) return "score-high"
  if (props.result.score >= 60) return "score-medium"
  return "score-low"
})

function severityText(s: string) {
  return ({ critical: "严重", high: "高", medium: "中", low: "低" } as Record<string, string>)[s] || s
}

function gasSaving(g: GasIssue) {
  if (!g.currentGas) return 0
  return Math.round((1 - g.optimizedGas / g.currentGas) * 100)
}
</script>

<style scoped>
.result-section { margin-top: 2rem; }
.score-card { border-radius: 16px; padding: 2rem; text-align: center; color: white; margin-bottom: 1rem; }
.score-high { background: linear-gradient(135deg, #10b981, #059669); }
.score-medium { background: linear-gradient(135deg, #f59e0b, #d97706); }
.score-low { background: linear-gradient(135deg, #ef4444, #dc2626); }
.score-label { font-size: 0.875rem; opacity: 0.9; margin-bottom: 0.5rem; }
.score-value { font-size: 4rem; font-weight: 800; }
.score-grade { font-size: 1.25rem; opacity: 0.9; }
.score-thresholds { font-size: 0.75rem; opacity: 0.8; margin-top: 0.5rem; }
.version-card { background: white; border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1.5rem; border-left: 4px solid #7c3aed; }
.version-title { font-weight: 600; color: #7c3aed; margin-bottom: 0.25rem; }
.version-summary { color: #4b5563; font-size: 0.875rem; }
.vulnerabilities h3, .gas-section h3 { margin-bottom: 1rem; font-size: 1.125rem; }
.vuln-card { background: white; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; border-left: 4px solid; }
.vuln-card.critical { border-color: #dc2626; }
.vuln-card.high { border-color: #f59e0b; }
.vuln-card.medium { border-color: #3b82f6; }
.vuln-card.low { border-color: #6b7280; }
.vuln-header { display: flex; justify-content: space-between; margin-bottom: 0.75rem; }
.vuln-type { font-weight: 600; }
.vuln-severity { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; background: #fee2e2; color: #dc2626; }
.vuln-desc { color: #374151; margin-bottom: 0.5rem; }
.vuln-line { font-size: 0.8125rem; color: #6d28d9; margin-bottom: 0.5rem; }
.vuln-code { background: #0f172a; color: #e2e8f0; padding: 0.75rem 1rem; border-radius: 8px; font-size: 0.8125rem; overflow-x: auto; margin: 0 0 0.5rem; font-family: "Fira Code", monospace; white-space: pre; }
.vuln-suggest { font-size: 0.875rem; color: #6b7280; }
.gas-card { background: white; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
.gas-fn { font-weight: 600; color: #7c3aed; margin-bottom: 0.5rem; }
.gas-info { color: #059669; font-size: 0.875rem; margin-bottom: 0.5rem; }
.gas-suggest { font-size: 0.875rem; color: #6b7280; }
</style>
