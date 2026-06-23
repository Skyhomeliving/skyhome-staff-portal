(async () => {
  try {
    const res = await fetch('/api/completeness');
    if (!res.ok) return;
    const data = await res.json();
    if (!Array.isArray(data) || !data.length) return;
    const red = data.filter(s => s.rag === 'red').length;
    const amber = data.filter(s => s.rag === 'amber').length;
    const green = data.filter(s => s.rag === 'green').length;
    const panel = document.createElement('div');
    panel.style.cssText = 'background:#f8f9fa;border:1px solid #dee2e6;border-radius:8px;padding:14px 18px;margin-bottom:20px;font-family:inherit;font-size:13px';
    panel.innerHTML = `<div style="font-weight:600;margin-bottom:10px">${data.length} staff · <span style="color:#155724">${green} complete</span> · <span style="color:#856404">${amber} partial</span> · <span style="color:#721c24">${red} incomplete</span></div>${red > 0 ? `<details><summary style="cursor:pointer;color:#721c24;font-weight:600">${red} incomplete record(s)</summary><ul style="margin:6px 0 0 16px;color:#721c24">${data.filter(s=>s.rag==='red').map(s=>`<li><strong>${s.name}</strong> (${s.pct}%) — missing: ${s.missing.join(', ')}</li>`).join('')}</ul></details>` : ''}`;
    (document.querySelector('main') || document.body).prepend(panel);
  } catch(e) {}
})();
