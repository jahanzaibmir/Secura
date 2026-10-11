"""Native folder-picker upload.

The browser's real OS folder dialog (webkitdirectory) opens; files upload
to the backend with their relative paths and the folder's name. The
browser_base parameter controls where the browser sends them: behind
nginx it is the public origin (same-origin, no CORS), in development it
is the absolute backend URL.

Note: switching tabs mid UPLOAD aborts the browser transfer. Keep this
tab open until the status says the scan has started. After that, roam
freely; the backend owns the job.
"""
import streamlit.components.v1 as components


def render_folder_upload(backend_url: str, browser_base: str = "") -> None:
    base = (browser_base or backend_url).rstrip("/")
    html = f"""
    <div style="font-family:'JetBrains Mono',ui-monospace,Menlo,monospace;">
      <input id="vw-folder" type="file" webkitdirectory multiple
             style="display:none">
      <button id="vw-pick"
        style="background:#0a0a0a;color:#fafafa;border:1px solid #0a0a0c;
               border-radius:8px;padding:0.5rem 1.35rem;font-weight:600;
               font-size:0.82rem;cursor:pointer;letter-spacing:0.01em;
               min-height:2.45rem;white-space:nowrap;
               box-shadow:0 1px 2px rgba(10,10,10,0.08);
               transition:transform .15s,box-shadow .15s,background .15s;">
        Choose folder
      </button>
      <span id="vw-status"
        style="color:#8a8d93;font-size:0.78rem;margin-left:0.8rem;">
        Select a project folder. It uploads and scans automatically.
      </span>
    </div>
    <script>
      const BACKEND = '{base}';
      const fldr = document.getElementById('vw-folder');
      const btn = document.getElementById('vw-pick');
      const status = document.getElementById('vw-status');
      const reset = () => {{ btn.disabled = false; btn.style.opacity = 1; }};
      btn.onclick = () => fldr.click();

      fldr.onchange = async () => {{
        const files = [...fldr.files];
        if (!files.length) return;
        btn.disabled = true;
        btn.style.opacity = 0.6;
        status.textContent =
          'Uploading ' + files.length + ' file(s). Keep this tab open…';

        const fd = new FormData();
        const paths = [];
        files.forEach(f => {{
          fd.append('files', f, f.name);
          paths.push(f.webkitRelativePath || f.name);
        }});
        fd.append('paths', JSON.stringify(paths));
        fd.append('folder_name', (paths[0] || '').split('/')[0] || 'folder');

        let data;
        try {{
          const resp = await fetch(BACKEND + '/api/scan/upload',
                                   {{ method: 'POST', body: fd }});
          if (!resp.ok) {{
            let msg = 'Upload failed (HTTP ' + resp.status + ')';
            try {{
              const j = await resp.json();
              if (j.detail) msg = j.detail;
            }} catch (e) {{}}
            status.textContent = msg;
            reset();
            return;
          }}
          data = await resp.json();
        }} catch (err) {{
          status.textContent = 'Could not reach the backend: ' + err;
          reset();
          return;
        }}

        // The backend owns the job from here. Switching tabs is safe.
        status.textContent = 'Scan queued. Tracking progress…';
        const jobUrl = BACKEND + '/api/scan/' +
                       encodeURIComponent(data.job_id);
        const deadline = Date.now() + 31 * 60 * 1000;
        const timer = setInterval(async () => {{
          if (Date.now() > deadline) {{
            clearInterval(timer);
            status.textContent =
              'Still running. It will appear in Recent uploads below.';
            return;
          }}
          try {{
            const v = await (await fetch(jobUrl)).json();
            if (v.status === 'completed' && v.report) {{
              clearInterval(timer);
              status.textContent =
                'Done. ' + v.report.summary.total +
                ' finding(s). Open the Results tab.';
            }} else if (v.status === 'failed') {{
              clearInterval(timer);
              status.textContent =
                'Scan failed: ' + (v.error || 'unknown error');
              reset();
            }} else {{
              status.textContent =
                (v.current_stage || v.status) + ' · ' + v.progress + '%';
            }}
          }} catch (e) {{ /* transient. Keep polling. */ }}
        }}, 1500);
      }};
    </script>
    """
    components.html(html, height=70)
