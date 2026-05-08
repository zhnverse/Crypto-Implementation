// Sovereign Guard — app.js

// ── Password visibility toggle ─────────────────────────────────────────────
document.querySelectorAll('.toggle-pw').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    if (!target) return;
    target.type = target.type === 'password' ? 'text' : 'password';
    btn.textContent = target.type === 'password' ? '👁' : '🙈';
  });
});

// ── Password strength indicator ────────────────────────────────────────────
const pwInput = document.getElementById('password');
const pwStrength = document.getElementById('pwStrength');
if (pwInput && pwStrength) {
  pwInput.addEventListener('input', () => {
    const v = pwInput.value;
    let score = 0;
    if (v.length >= 8)  score++;
    if (v.length >= 12) score++;
    if (/[A-Z]/.test(v)) score++;
    if (/[0-9]/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;
    const colors = ['#ff4444','#ff8c00','#ffd740','#66bb6a','#00e676'];
    const widths  = ['20%','40%','60%','80%','100%'];
    pwStrength.style.background = colors[Math.max(0, score-1)] || '#333';
    pwStrength.style.width = widths[Math.max(0, score-1)] || '0%';
  });
}

// ── Auto-dismiss flash messages ────────────────────────────────────────────
document.querySelectorAll('.flash').forEach(el => {
  setTimeout(() => {
    el.style.transition = 'opacity .5s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 500);
  }, 5000);
});

// ── OTP auto-submit ────────────────────────────────────────────────────────
const otpInput = document.getElementById('code');
if (otpInput) {
  otpInput.addEventListener('input', function() {
    this.value = this.value.replace(/\D/g, '').slice(0, 6);
    if (this.value.length === 6) {
      const form = this.closest('form');
      if (form) setTimeout(() => form.submit(), 200);
    }
  });
}

// ── Register form spinner ──────────────────────────────────────────────────
const regForm = document.getElementById('registerForm');
if (regForm) {
  regForm.addEventListener('submit', () => {
    const btn = document.getElementById('registerBtn');
    if (btn) {
      btn.querySelector('.btn-text').textContent = 'Generating keys…';
      btn.disabled = true;
    }
  });
}

// ── Confirm delete forms ───────────────────────────────────────────────────
document.querySelectorAll('form[data-confirm]').forEach(form => {
  form.addEventListener('submit', e => {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
});

console.log('%c🛡 Sovereign Guard', 'color:#6c63ff;font-size:1.2rem;font-weight:bold;');
console.log('%cRSA-2048 + ECC P-256 + HMAC-SHA256 + TOTP — all from scratch.', 'color:#8890a4');
