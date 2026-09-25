import { createRouter, createWebHistory } from 'vue-router'
import AuditView from '@/views/AuditView.vue'
import PatternsView from '@/views/PatternsView.vue'
import HistoryView from '@/views/HistoryView.vue'
import AuditDetailView from '@/views/AuditDetailView.vue'
import GasView from '@/views/GasView.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", component: AuditView, meta: { title: "合约审计" } },
    { path: "/patterns", component: PatternsView, meta: { title: "漏洞模式库" } },
    { path: "/history", component: HistoryView, meta: { title: "审计历史" } },
    { path: "/history/:id", component: AuditDetailView, meta: { title: "审计详情" } },
    { path: "/gas", component: GasView, meta: { title: "Gas分析" } }
  ]
})

export default router
