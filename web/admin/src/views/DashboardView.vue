<script setup lang="ts">
const cards = [
  {
    title: 'Health Endpoint',
    value: 'GET /healthz',
    detail: 'Backend health check is available for compose-based startup validation.',
  },
  {
    title: 'Readiness Endpoint',
    value: 'GET /readyz',
    detail: 'Current readiness is config-based and will be upgraded in a later task.',
  },
  {
    title: 'Frontend Status',
    value: 'Vue 3 + Vite',
    detail: 'The admin console routing shell is ready for subsequent feature tasks.',
  },
]
</script>

<template>
  <section class="dashboard">
    <div class="hero">
      <p class="label">Bootstrap</p>
      <h2>Dashboard</h2>
      <p class="description">
        This is the initial admin shell for openauthing. Business modules will be added in later tasks.
      </p>
    </div>

    <div class="grid">
      <article v-for="card in cards" :key="card.title" class="metric-card">
        <p class="metric-title">{{ card.title }}</p>
        <h3>{{ card.value }}</h3>
        <p class="metric-detail">{{ card.detail }}</p>
      </article>
    </div>
  </section>
</template>

<style scoped>
.dashboard {
  display: grid;
  gap: 20px;
}

.hero,
.metric-card {
  padding: 28px;
  border-radius: 24px;
  background: rgba(255, 255, 255, 0.88);
  border: 1px solid rgba(15, 23, 42, 0.08);
  box-shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
}

.label,
.metric-title {
  margin: 0 0 8px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #0f766e;
}

h2 {
  margin: 0;
  font-size: 32px;
}

h3 {
  margin: 0;
  font-size: 24px;
}

.description,
.metric-detail {
  margin: 12px 0 0;
  line-height: 1.6;
  color: #334155;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
}
</style>
