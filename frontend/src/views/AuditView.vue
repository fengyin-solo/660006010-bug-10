<template>
  <div class="audit">
    <h2>智能合约安全审计</h2>
    <div class="upload-section">
      <textarea v-model="contractCode" class="code-editor" placeholder="// 粘贴 Solidity 合约代码..."></textarea>
      <div class="toolbar">
        <input v-model="filename" placeholder="文件名.sol" class="filename-input" />
        <button @click="runAudit(false)" class="btn-primary" :disabled="!contractCode || isAuditing">
          {{ isAuditing ? "审计中..." : "开始审计" }}
        </button>
      </div>
      <div v-if="errorMsg" class="error-bar">
        <span>{{ errorMsg }}</span>
        <button v-if="errorRetryable" class="btn-retry" @click="runAudit(true)">重试</button>
      </div>
    </div>

    <AuditResultPanel v-if="result" :result="result" />
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue"
import { useAuditStore, AuditError, type AuditResult } from "@/store"
import AuditResultPanel from "@/components/AuditResultPanel.vue"

const contractCode = ref(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}`)
const filename = ref("SimpleBank.sol")
const isAuditing = ref(false)
const errorMsg = ref("")
const errorRetryable = ref(false)
const result = ref<AuditResult | null>(null)

const store = useAuditStore()

async function runAudit(isRetry: boolean) {
  isAuditing.value = true
  errorMsg.value = ""
  try {
    result.value = isRetry
      ? await store.retryAudit(contractCode.value, filename.value)
      : await store.uploadAndAudit(contractCode.value, filename.value)
  } catch (err) {
    if (err instanceof AuditError) {
      errorMsg.value = err.message
      errorRetryable.value = err.retryable
    } else {
      errorMsg.value = "扫描失败，请重试"
      errorRetryable.value = true
    }
  } finally {
    isAuditing.value = false
  }
}
</script>

<style scoped>
.audit { max-width: 1000px; }
.code-editor { width: 100%; height: 300px; font-family: "Fira Code", monospace; font-size: 0.875rem; padding: 1rem; border: 1px solid #d1d5db; border-radius: 8px; background: #1e1e1e; color: #d4d4d4; resize: vertical; }
.toolbar { display: flex; gap: 1rem; margin: 1rem 0; align-items: center; }
.filename-input { padding: 0.5rem 1rem; border: 1px solid #d1d5db; border-radius: 8px; flex: 1; }
.btn-primary { background: #8b5cf6; color: white; border: none; padding: 0.625rem 1.5rem; border-radius: 8px; cursor: pointer; white-space: nowrap; }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
.error-bar { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; padding: 0.75rem 1rem; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; color: #b91c1c; }
.btn-retry { background: #dc2626; color: white; border: none; padding: 0.375rem 1rem; border-radius: 6px; cursor: pointer; }
</style>
