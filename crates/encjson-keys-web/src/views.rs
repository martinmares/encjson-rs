fn layout(title: &str, active: &str, body: &str) -> String {
    let dash_active = if active == "dashboard" { "active" } else { "" };
    let boot_active = if active == "bootstrap" { "active" } else { "" };
    let keys_active = if active == "keys" { "active" } else { "" };
    let req_active = if active == "requests" { "active" } else { "" };
    let ten_active = if active == "tenants" { "active" } else { "" };

    format!(
        r#"<!doctype html>
<html lang="en" data-bs-theme="auto">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.4.0/dist/css/tabler.min.css">
  <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
  <script>
    (() => {{
      const key = "encjson-theme";
      const stored = localStorage.getItem(key) || "auto";
      const root = document.documentElement;
      const apply = (mode) => {{
        if (mode === "auto") {{
          const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          root.setAttribute("data-bs-theme", dark ? "dark" : "light");
        }} else {{
          root.setAttribute("data-bs-theme", mode);
        }}
      }};
      apply(stored);
      window.setThemeMode = (mode) => {{
        localStorage.setItem(key, mode);
        apply(mode);
      }};
    }})();
  </script>
</head>
<body>
  <div class="page">
    <header class="navbar navbar-expand-md d-print-none">
      <div class="container-xl">
        <h1 class="navbar-brand navbar-brand-autodark mb-0">encjson-keys-web</h1>
        <div class="ms-auto d-flex gap-2">
          <button class="btn btn-outline-secondary btn-sm" onclick="setThemeMode('light')">Light</button>
          <button class="btn btn-outline-secondary btn-sm" onclick="setThemeMode('dark')">Dark</button>
          <button class="btn btn-primary btn-sm" onclick="setThemeMode('auto')">Auto</button>
        </div>
      </div>
    </header>
    <header class="navbar-expand-md">
      <div class="collapse navbar-collapse show">
        <div class="navbar">
          <div class="container-xl">
            <ul class="navbar-nav">
              <li class="nav-item {dash_active}"><a class="nav-link" href="/ui"><span class="nav-link-title">Dashboard</span></a></li>
              <li class="nav-item {boot_active}"><a class="nav-link" href="/ui/bootstrap"><span class="nav-link-title">Bootstrap</span></a></li>
              <li class="nav-item {keys_active}"><a class="nav-link" href="/ui/keys"><span class="nav-link-title">Keys</span></a></li>
              <li class="nav-item {req_active}"><a class="nav-link" href="/ui/requests"><span class="nav-link-title">Requests</span></a></li>
              <li class="nav-item {ten_active}"><a class="nav-link" href="/ui/tenants"><span class="nav-link-title">Tenants</span></a></li>
            </ul>
          </div>
        </div>
      </div>
    </header>
    <div class="page-wrapper">
      <div class="page-body">
        <div class="container-xl">
          {body}
        </div>
      </div>
    </div>
  </div>
</body>
</html>"#
    )
}

pub fn dashboard_html() -> String {
    let body = r#"
<div class="row row-cards" x-data="dashboard()">
  <div class="col-md-4">
    <div class="card"><div class="card-body"><div class="text-secondary">Keys</div><div class="h1 m-0" x-text="stats.keys"></div></div></div>
  </div>
  <div class="col-md-4">
    <div class="card"><div class="card-body"><div class="text-secondary">Pending Requests</div><div class="h1 m-0" x-text="stats.pending"></div></div></div>
  </div>
  <div class="col-md-4">
    <div class="card"><div class="card-body"><div class="text-secondary">Tenants</div><div class="h1 m-0" x-text="stats.tenants"></div></div></div>
  </div>
</div>
<script>
function dashboard() {
  return {
    stats: { keys: 0, pending: 0, tenants: 0 },
    async load() {
      const [k, r, t] = await Promise.all([
        fetch('/api/v1/ui/keys').then(x => x.json()),
        fetch('/api/v1/ui/requests?status=pending').then(x => x.json()),
        fetch('/api/v1/ui/tenants').then(x => x.json())
      ]);
      this.stats.keys = k.length || 0;
      this.stats.pending = r.length || 0;
      this.stats.tenants = t.length || 0;
    },
    init() {
      this.load();
      const es = new EventSource('/api/v1/ui/events');
      es.addEventListener('requests.pending_count', e => {
        const p = JSON.parse(e.data);
        this.stats.pending = p.pending_count;
      });
    }
  }
}
</script>
"#;
    layout("Dashboard", "dashboard", body)
}

pub fn bootstrap_html() -> String {
    let body = r#"
<div class="card" x-data="bootstrapPage()">
  <div class="card-header"><h3 class="card-title">Bootstrap Import</h3></div>
  <div class="card-body">
    <p class="text-secondary">Imports one keypair from configured source and upserts it to keys-server storage.</p>
    <div class="row g-2 mb-3">
      <div class="col-md-3"><input class="form-control" placeholder="tenant (e.g. tsm)" x-model="tenant"></div>
      <div class="col-md-2"><input class="form-control" placeholder="env (e.g. test)" x-model="env"></div>
      <div class="col-md-2">
        <select class="form-select" x-model="status">
          <option value="active">active</option>
          <option value="revoked">revoked</option>
        </select>
      </div>
      <div class="col-md-4"><input class="form-control" placeholder="note" x-model="note"></div>
      <div class="col-md-1 d-grid">
        <button class="btn btn-primary" :disabled="busy" @click="apply()">Apply</button>
      </div>
    </div>
    <div class="mb-3 d-flex gap-2 flex-wrap">
      <template x-for="item in quickEnvs" :key="item">
        <button
          class="btn btn-sm"
          :class="env === item ? 'btn-primary' : 'btn-outline-secondary'"
          @click="env = item"
          x-text="item"
        ></button>
      </template>
    </div>
    <template x-if="msg"><div class="alert alert-success" x-text="msg"></div></template>
    <template x-if="err"><div class="alert alert-danger" x-text="err"></div></template>
    <template x-if="result">
      <div class="table-responsive mt-3">
        <table class="table table-vcenter card-table">
          <tbody>
            <tr><th>Public key</th><td class="font-monospace" x-text="result.public_hex"></td></tr>
            <tr><th>Tenant</th><td x-text="result.tenant"></td></tr>
            <tr><th>Env</th><td x-text="result.env"></td></tr>
            <tr><th>Status</th><td><span class="badge" :class="statusBadgeClass(result.status)" x-text="result.status"></span></td></tr>
            <tr><th>Note</th><td x-text="result.note"></td></tr>
            <tr>
              <th>Tags</th>
              <td>
                <template x-for="tag in (result.tags || [])" :key="tag">
                  <span class="badge me-1 mb-1" :class="tagBadgeClass(tag)" x-text="tag"></span>
                </template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
    <div class="mt-4">
      <h4 class="mb-2">Recent bootstrap imports</h4>
      <div class="table-responsive">
        <table class="table table-vcenter card-table">
          <thead><tr><th>Updated</th><th>Public Key</th><th>Tenant</th><th>Status</th><th>Tags</th></tr></thead>
          <tbody>
            <template x-for="row in history" :key="row.public_hex + ':' + row.updated_at">
              <tr>
                <td x-text="row.updated_at"></td>
                <td class="font-monospace" x-text="row.public_hex"></td>
                <td x-text="row.tenant"></td>
                <td><span class="badge" :class="statusBadgeClass(row.status)" x-text="row.status"></span></td>
                <td>
                  <template x-for="tag in (row.tags || [])" :key="tag">
                    <span class="badge me-1 mb-1" :class="tagBadgeClass(tag)" x-text="tag"></span>
                  </template>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
<script>
function bootstrapPage() {
  return {
    tenant: '', env: '', status: 'active', note: 'manual bootstrap',
    quickEnvs: ['dev', 'test', 'ref', 'prod', 'prod2'],
    busy: false, msg: '', err: '', result: null, history: [],
    roleTenants: [],
    roleEnvs: [],
    statusBadgeClass(status) {
      if (status === 'active') return 'bg-green-lt text-green-fg';
      if (status === 'revoked') return 'bg-red-lt text-red-fg';
      return 'bg-secondary-lt text-secondary-fg';
    },
    tagBadgeClass(tag) {
      if (tag === 'bootstrap') return 'bg-blue-lt text-blue-fg';
      if ((tag || '').startsWith('source:')) return 'bg-yellow-lt text-yellow-fg';
      if ((tag || '').startsWith('env:')) return 'bg-azure-lt text-azure-fg';
      return 'bg-secondary-lt text-secondary-fg';
    },
    parseRoleValues(prefix, roles) {
      return (roles || [])
        .filter(r => r.startsWith(prefix))
        .map(r => r.substring(prefix.length))
        .filter(v => v && v.trim().length > 0);
    },
    async prefillFromSession() {
      try {
        const me = await fetch('/api/v1/ui/me').then(x => x.json());
        this.roleTenants = this.parseRoleValues('encjson:tenant:', me.roles);
        this.roleEnvs = this.parseRoleValues('encjson:env:', me.roles);
        if (!this.tenant && this.roleTenants.length > 0) this.tenant = this.roleTenants[0];
        if (!this.env && this.roleEnvs.length > 0) this.env = this.roleEnvs[0];
      } catch (_) {}
    },
    async loadHistory() {
      try {
        const rows = await fetch('/api/v1/ui/keys?q=bootstrap').then(x => x.json());
        this.history = (rows || [])
          .filter(r => (r.tags || []).includes('bootstrap'))
          .sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''))
          .slice(0, 10);
      } catch (_) {
        this.history = [];
      }
    },
    async apply() {
      this.msg = ''; this.err = ''; this.result = null;
      if (!this.tenant.trim() || !this.env.trim()) {
        this.err = 'tenant and env are required';
        return;
      }
      if (!window.confirm(`Apply bootstrap import for tenant='${this.tenant.trim()}', env='${this.env.trim()}'?`)) {
        return;
      }
      this.busy = true;
      try {
        const resp = await fetch('/api/v1/ui/bootstrap/import', {
          method: 'POST',
          headers: {'content-type': 'application/json'},
          body: JSON.stringify({
            tenant: this.tenant.trim(),
            env: this.env.trim(),
            status: this.status,
            note: this.note,
          }),
        });
        const body = await resp.text();
        if (!resp.ok) {
          this.err = body || ('HTTP ' + resp.status);
          return;
        }
        this.result = JSON.parse(body);
        this.msg = 'Bootstrap import applied.';
        await this.loadHistory();
      } catch (e) {
        this.err = String(e);
      } finally {
        this.busy = false;
      }
    },
    async init() {
      await this.prefillFromSession();
      await this.loadHistory();
    },
  }
}
</script>
"#;
    layout("Bootstrap", "bootstrap", body)
}

pub fn keys_html() -> String {
    let body = r#"
<div class="card" x-data="keysPage()">
  <div class="card-header"><h3 class="card-title">Keys</h3></div>
  <div class="card-body">
    <div class="mb-3"><input class="form-control" placeholder="Filter by tenant/public key" x-model="q" @input.debounce.250ms="load()"></div>
    <div class="table-responsive">
      <table class="table table-vcenter card-table">
        <thead><tr><th>Public Key</th><th>Tenant</th><th>Status</th><th>Tags</th></tr></thead>
        <tbody>
          <template x-for="row in rows" :key="row.public_hex">
            <tr>
              <td class="font-monospace" x-text="row.public_hex"></td>
              <td x-text="row.tenant"></td>
              <td x-text="row.status"></td>
              <td x-text="(row.tags || []).join(', ')"></td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</div>
<script>
function keysPage() {
  return {
    q: '', rows: [],
    async load() {
      const params = this.q ? ('?q=' + encodeURIComponent(this.q)) : '';
      this.rows = await fetch('/api/v1/ui/keys' + params).then(x => x.json());
    },
    init() { this.load(); }
  }
}
</script>
"#;
    layout("Keys", "keys", body)
}

pub fn requests_html() -> String {
    let body = r#"
<div class="card" x-data="requestsPage()">
  <div class="card-header"><h3 class="card-title">Requests</h3></div>
  <div class="card-body">
    <div class="table-responsive">
      <table class="table table-vcenter card-table">
        <thead><tr><th>ID</th><th>Public Key</th><th>Tenant</th><th>Status</th><th></th></tr></thead>
        <tbody>
          <template x-for="row in rows" :key="row.id">
            <tr>
              <td x-text="row.id"></td>
              <td class="font-monospace" x-text="row.public_hex"></td>
              <td x-text="row.tenant"></td>
              <td x-text="row.status"></td>
              <td>
                <button class="btn btn-sm btn-success" @click="approve(row.id)">Approve</button>
                <button class="btn btn-sm btn-danger" @click="reject(row.id)">Reject</button>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</div>
<script>
function requestsPage() {
  return {
    rows: [],
    async load() { this.rows = await fetch('/api/v1/ui/requests?status=pending').then(x => x.json()); },
    async approve(id) { await fetch('/api/v1/ui/requests/' + id + '/approve', {method:'POST', headers:{'content-type':'application/json'}, body:'{}'}); await this.load(); },
    async reject(id) { await fetch('/api/v1/ui/requests/' + id + '/reject', {method:'POST', headers:{'content-type':'application/json'}, body:'{}'}); await this.load(); },
    init() { this.load(); }
  }
}
</script>
"#;
    layout("Requests", "requests", body)
}

pub fn tenants_html() -> String {
    let body = r#"
<div class="card" x-data="tenantsPage()">
  <div class="card-header"><h3 class="card-title">Tenants</h3></div>
  <div class="card-body">
    <div class="d-flex gap-2 mb-3">
      <input class="form-control" placeholder="New tenant name" x-model="newTenant">
      <button class="btn btn-primary" @click="add()">Add</button>
    </div>
    <div class="table-responsive">
      <table class="table table-vcenter card-table">
        <thead><tr><th>Name</th><th>Created</th><th></th></tr></thead>
        <tbody>
          <template x-for="row in rows" :key="row.name">
            <tr>
              <td x-text="row.name"></td>
              <td x-text="row.created_at"></td>
              <td><button class="btn btn-sm btn-danger" @click="del(row.name)">Delete</button></td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</div>
<script>
function tenantsPage() {
  return {
    rows: [], newTenant: '',
    async load() { this.rows = await fetch('/api/v1/ui/tenants').then(x => x.json()); },
    async add() {
      if (!this.newTenant.trim()) return;
      await fetch('/api/v1/ui/tenants', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({name:this.newTenant})});
      this.newTenant=''; await this.load();
    },
    async del(name) { await fetch('/api/v1/ui/tenants/' + encodeURIComponent(name), {method:'DELETE'}); await this.load(); },
    init() { this.load(); }
  }
}
</script>
"#;
    layout("Tenants", "tenants", body)
}
