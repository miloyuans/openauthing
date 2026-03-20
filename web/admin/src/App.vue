<template>
  <div class="app-shell">
    <header class="topbar">
      <div>
        <p class="eyebrow">openauthing</p>
        <h1>Admin Console</h1>
      </div>
      <nav class="nav">
        <RouterLink to="/login">Login</RouterLink>
        <RouterLink to="/dashboard">Dashboard</RouterLink>
      </nav>
    </header>

    <main class="content">
      <RouterView />
    </main>
  </div>
</template>

<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
</script>

<style scoped>
.app-shell {
  min-height: 100vh;
  background:
    radial-gradient(circle at top left, rgba(14, 165, 233, 0.18), transparent 30%),
    linear-gradient(135deg, #ecfeff 0%, #f8fafc 55%, #fefce8 100%);
  color: #0f172a;
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 24px 32px;
}

.eyebrow {
  margin: 0;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #0369a1;
}

h1 {
  margin: 4px 0 0;
  font-size: 30px;
}

.nav {
  display: flex;
  gap: 12px;
}

.nav a {
  padding: 10px 14px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.72);
  color: #0f172a;
  text-decoration: none;
  font-weight: 600;
}

.nav a.router-link-active {
  background: #0f766e;
  color: #fff;
}

.content {
  padding: 0 32px 32px;
}

@media (max-width: 720px) {
  .topbar {
    flex-direction: column;
    align-items: flex-start;
    padding: 20px;
  }

  .content {
    padding: 0 20px 20px;
  }
}
</style>
