<template>
  <section class="card">
    <p class="label">Placeholder</p>
    <h2>Login</h2>
    <p class="description">
      This page is reserved for the admin login flow in a later task.
    </p>
    <form class="form" @submit.prevent>
      <label>
        <span>Username</span>
        <input type="text" placeholder="admin@example.com" disabled />
      </label>
      <label>
        <span>Password</span>
        <input type="password" placeholder="********" disabled />
      </label>
      <button type="submit" disabled>Sign in</button>
    </form>
  </section>
</template>

<style scoped>
.card {
  width: min(520px, 100%);
  padding: 28px;
  border-radius: 24px;
  background: rgba(255, 255, 255, 0.88);
  border: 1px solid rgba(15, 23, 42, 0.08);
  box-shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
}

.label {
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

.description {
  margin: 12px 0 0;
  line-height: 1.6;
  color: #334155;
}

.form {
  display: grid;
  gap: 16px;
  margin-top: 24px;
}

label {
  display: grid;
  gap: 8px;
}

span {
  font-weight: 600;
}

input,
button {
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid rgba(15, 23, 42, 0.12);
  font: inherit;
}

button {
  background: #0f766e;
  color: #fff;
}
</style>
