css = open('static/style.css').read()
# Append premium overrides
extra = """
/* ── PREMIUM OVERRIDES ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,300;0,14..32,800&display=swap');

body { background: radial-gradient(ellipse at 20% 0%, #0d0f1e 0%, #070910 60%); }

/* Animated mesh background */
body::before {
  content:''; position:fixed; inset:0; z-index:-1;
  background:
    radial-gradient(ellipse 80% 50% at 10% 20%, rgba(108,63,255,.18) 0%, transparent 60%),
    radial-gradient(ellipse 60% 40% at 90% 80%, rgba(0,210,255,.12) 0%, transparent 60%),
    radial-gradient(ellipse 50% 30% at 50% 50%, rgba(255,77,148,.06) 0%, transparent 60%);
  pointer-events:none;
}

/* Navbar glow */
.navbar {
  background: rgba(7,9,16,.92);
  border-bottom: 1px solid rgba(108,99,255,.25);
  box-shadow: 0 1px 32px rgba(108,99,255,.12);
}
.nav-brand { background: linear-gradient(90deg,#a78bfa,#38bdf8); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; font-size:1.2rem; }

/* Glass cards */
.glass-card, .feature-card, .post-card, .auth-card, .key-mgmt-card {
  background: rgba(255,255,255,.035);
  border: 1px solid rgba(255,255,255,.09);
  backdrop-filter: blur(24px) saturate(180%);
  box-shadow: 0 8px 32px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.07);
}

/* Feature card hover glow */
.feature-card:hover {
  border-color: rgba(108,99,255,.5);
  box-shadow: 0 0 0 1px rgba(108,99,255,.3), 0 16px 48px rgba(108,99,255,.2), inset 0 1px 0 rgba(255,255,255,.1);
  transform: translateY(-6px);
}
.feature-icon { font-size:2.4rem; filter:drop-shadow(0 0 12px rgba(108,99,255,.6)); }

/* Hero */
.hero-title { font-size: clamp(3rem,8vw,5.5rem); }
.hero-glow { width:900px; height:600px; background:radial-gradient(ellipse,rgba(108,99,255,.3) 0%,transparent 70%); }
.hero-badge { animation: pulse-badge 3s ease-in-out infinite; }
@keyframes pulse-badge { 0%,100%{box-shadow:0 0 0 0 rgba(108,99,255,.4)} 50%{box-shadow:0 0 0 8px rgba(108,99,255,0)} }

/* Buttons */
.btn-primary {
  background: linear-gradient(135deg,#7c3aed,#2563eb);
  box-shadow: 0 4px 20px rgba(108,99,255,.35);
  position:relative; overflow:hidden;
}
.btn-primary::after { content:''; position:absolute; inset:0; background:linear-gradient(135deg,rgba(255,255,255,.15),transparent); }
.btn-primary:hover { transform:translateY(-2px); box-shadow:0 8px 32px rgba(108,99,255,.5); }

/* Inputs */
.form-group input, .form-group textarea, .form-group select {
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.1);
  transition: all .25s;
}
.form-group input:focus, .form-group textarea:focus {
  border-color: #7c3aed;
  background: rgba(124,58,237,.08);
  box-shadow: 0 0 0 4px rgba(124,58,237,.15);
}

/* Posts */
.post-card {
  transition: all .3s cubic-bezier(.4,0,.2,1);
  position:relative; overflow:hidden;
}
.post-card::before {
  content:''; position:absolute; top:0; left:0; right:0; height:2px;
  background: linear-gradient(90deg,#7c3aed,#2563eb,#06b6d4);
  opacity:0; transition: opacity .3s;
}
.post-card:hover::before { opacity:1; }
.post-card:hover { transform:translateY(-4px); box-shadow:0 20px 60px rgba(0,0,0,.6); }
.post-title { font-size:1.1rem; font-weight:700; background:linear-gradient(90deg,#e2e8f0,#94a3b8); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }

/* Auth */
.auth-card {
  background: rgba(10,12,24,.85);
  border: 1px solid rgba(255,255,255,.1);
  box-shadow: 0 32px 80px rgba(0,0,0,.7), inset 0 1px 0 rgba(255,255,255,.08);
}
.auth-icon { font-size:3rem; filter:drop-shadow(0 0 20px rgba(124,58,237,.8)); animation: float 4s ease-in-out infinite; }
@keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-8px)} }

/* Live TOTP code */
.live-code { background:linear-gradient(90deg,#a78bfa,#38bdf8); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }

/* Profile avatar */
.profile-avatar {
  background: linear-gradient(135deg,#7c3aed,#06b6d4);
  box-shadow: 0 8px 32px rgba(124,58,237,.5);
  border: 2px solid rgba(255,255,255,.15);
}

/* Tables */
.admin-table th { background: rgba(124,58,237,.1); }
.admin-table tbody tr:hover { background: rgba(124,58,237,.06); }

/* Badges */
.badge { background: rgba(124,58,237,.2); border:1px solid rgba(124,58,237,.4); color:#a78bfa; }
.badge-inline { background: rgba(124,58,237,.2); border:1px solid rgba(124,58,237,.3); color:#c4b5fd; }

/* Page header */
.page-title { background:linear-gradient(90deg,#e2e8f0,#94a3b8); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }

/* Scroll animations */
@keyframes slide-up { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
.post-card { animation: slide-up .4s ease both; }
.feature-card { animation: slide-up .5s ease both; }
.feature-card:nth-child(2){animation-delay:.05s}
.feature-card:nth-child(3){animation-delay:.1s}
.feature-card:nth-child(4){animation-delay:.15s}
.feature-card:nth-child(5){animation-delay:.2s}
.feature-card:nth-child(6){animation-delay:.25s}

/* Footer */
.footer { background:rgba(7,9,16,.95); border-top:1px solid rgba(124,58,237,.2); }

/* Scrollbar */
::-webkit-scrollbar-thumb { background:linear-gradient(180deg,#7c3aed,#2563eb); }

/* Integrity badges */
.integrity-badge.ok { box-shadow:0 0 8px rgba(0,230,118,.2); }
.integrity-badge.bad { box-shadow:0 0 8px rgba(255,107,107,.2); animation:blink 1.5s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.6} }

/* Crypto info box */
.crypto-info-box { background:rgba(124,58,237,.07); border:1px solid rgba(124,58,237,.25); backdrop-filter:blur(8px); }

/* Key cards */
.km-key-block { background:rgba(0,0,0,.3); border:1px solid rgba(255,255,255,.06); }
.km-key-type { color:#a78bfa; }

/* Empty state icon */
.empty-icon { filter:drop-shadow(0 0 24px rgba(124,58,237,.4)); }
"""
with open('static/style.css', 'a') as f:
    f.write(extra)
print("Premium CSS applied!")
