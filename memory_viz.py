#!/usr/bin/env python3
import subprocess, json, time, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>메모리 실시간 시각화</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0e0e10;color:#e2e2e6;padding:20px}
h1{font-size:18px;font-weight:500;margin-bottom:16px;color:#c8c8d0}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.stat{background:#1a1a1f;border:0.5px solid #2e2e38;border-radius:10px;padding:12px;text-align:center}
.stat-val{font-size:22px;font-weight:500;color:#e2e2e6}
.stat-lbl{font-size:11px;color:#555;margin-top:3px}
.box{background:#1a1a1f;border:0.5px solid #2e2e38;border-radius:12px;overflow:hidden;margin-bottom:12px}
.bh{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:0.5px solid #2e2e38;background:#141418}
.bh span{font-size:12px;color:#555}
.bh .tip{font-size:12px;color:#888;min-width:200px;text-align:right}
#grid{display:grid;grid-template-columns:repeat(40,1fr);gap:2px;padding:12px}
.cell{height:20px;border-radius:3px;background:#222228;border:0.5px solid #2e2e38;transition:opacity .1s;cursor:default}
.legend{display:flex;flex-wrap:wrap;gap:8px;padding:12px 14px;border-top:0.5px solid #2e2e38}
.li{display:flex;align-items:center;gap:5px;font-size:12px;color:#777}
.ld{width:11px;height:11px;border-radius:2px;flex-shrink:0}
.proc-list{width:100%}
.proc-list table{width:100%;border-collapse:collapse;font-size:13px}
.proc-list td,.proc-list th{padding:7px 14px;text-align:left;border-bottom:0.5px solid #2e2e38;color:#c8c8d0}
.proc-list th{font-size:11px;color:#555;font-weight:400;background:#141418}
.bar-bg{background:#222228;border-radius:3px;height:8px;width:100%;min-width:60px}
.bar-fg{height:8px;border-radius:3px;transition:width .4s}
.dot{width:10px;height:10px;border-radius:2px;display:inline-block;margin-right:5px;flex-shrink:0}
.badge{font-size:10px;padding:2px 6px;border-radius:4px;background:#222228;color:#666;border:0.5px solid #2e2e38}
#status{font-size:11px;color:#555}
.pulse{animation:pulse 1s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
</style>
</head>
<body>
<h1>메모리 실시간 시각화 <span id="status" class="pulse">● 연결 중...</span></h1>

<div class="stats">
  <div class="stat"><div class="stat-val" id="s-total">-</div><div class="stat-lbl">총 메모리</div></div>
  <div class="stat"><div class="stat-val" id="s-used">-</div><div class="stat-lbl">사용 중</div></div>
  <div class="stat"><div class="stat-val" id="s-free">-</div><div class="stat-lbl">여유</div></div>
  <div class="stat"><div class="stat-val" id="s-procs">-</div><div class="stat-lbl">프로세스 수</div></div>
</div>

<div class="box">
  <div class="bh">
    <span>물리 메모리 페이지 맵 (각 칸 = 페이지 그룹, 색 = 프로세스)</span>
    <span class="tip" id="tip">칸에 마우스를 올려보세요</span>
  </div>
  <div id="grid"></div>
  <div class="legend" id="legend"></div>
</div>

<div class="box proc-list">
  <table>
    <thead><tr><th>프로세스</th><th>PID</th><th>메모리 %</th><th>RSS</th><th></th></tr></thead>
    <tbody id="proc-tbody"></tbody>
  </table>
</div>

<script>
const PALETTE=[
  ['#5BA8F0','#0e2035'],['#2DC98E','#092e1f'],['#E87BAA','#2a0f1c'],
  ['#E8A030','#2a1c06'],['#8B7EE8','#141028'],['#F07850','#2a1108'],
  ['#86C440','#182208'],['#F07070','#2a0e0e'],['#2BBFA0','#082b24'],
  ['#D06090','#280d1c'],['#4090D8','#0c1e38'],['#C09030','#221808']
];
const colorMap={};
let palIdx=0;

function getColor(name){
  if(!colorMap[name]){colorMap[name]=PALETTE[palIdx%PALETTE.length];palIdx++;}
  return colorMap[name];
}

async function fetchData(){
  try{
    const r=await fetch('/data');
    const d=await r.json();
    update(d);
    document.getElementById('status').textContent='● 실시간';
    document.getElementById('status').style.animation='none';
    document.getElementById('status').style.color='#1D9E75';
  }catch(e){
    document.getElementById('status').textContent='● 연결 끊김';
    document.getElementById('status').style.color='#E24B4A';
  }
}

function update(d){
  document.getElementById('s-total').textContent=d.total_gb.toFixed(1)+'GB';
  document.getElementById('s-used').textContent=d.used_pct.toFixed(1)+'%';
  document.getElementById('s-free').textContent=(100-d.used_pct).toFixed(1)+'%';
  document.getElementById('s-procs').textContent=d.procs.length;

  const CELLS=200;
  const pages=[];
  const top=d.procs.slice(0,12);
  for(const p of top){
    const cnt=Math.max(1,Math.round((p.mem/100)*CELLS));
    for(let i=0;i<cnt;i++)pages.push(p);
  }
  const free=Math.max(0,CELLS-pages.length);
  for(let i=0;i<free;i++)pages.push(null);
  for(let i=pages.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[pages[i],pages[j]]=[pages[j],pages[i]];}

  const grid=document.getElementById('grid');
  const cells=grid.querySelectorAll('.cell');
  if(cells.length!==CELLS){
    grid.innerHTML='';
    for(let i=0;i<CELLS;i++){
      const div=document.createElement('div');div.className='cell';
      div.addEventListener('mouseenter',()=>{
        const p=pages[i];
        document.getElementById('tip').textContent=p?`${p.name} (PID ${p.pid}) — RSS ${p.rss}`:'빈 페이지 (free)';
      });
      grid.appendChild(div);
    }
  }
  const allCells=grid.querySelectorAll('.cell');
  pages.forEach((p,i)=>{
    const el=allCells[i];
    if(p){const[s,f]=getColor(p.name);el.style.background=f;el.style.borderColor=s+'99';}
    else{el.style.background='#222228';el.style.borderColor='#2e2e38';}
  });

  const legend=document.getElementById('legend');
  legend.innerHTML='<div class="li"><div class="ld" style="background:#222228;border:0.5px solid #2e2e38"></div><span>빈 페이지</span></div>';
  for(const p of top){
    const[s,f]=getColor(p.name);
    const li=document.createElement('div');li.className='li';
    li.innerHTML=`<div class="ld" style="background:${f};border:0.5px solid ${s}"></div><span>${p.name}</span>`;
    legend.appendChild(li);
  }

  const tbody=document.getElementById('proc-tbody');
  tbody.innerHTML='';
  for(const p of d.procs.slice(0,15)){
    const[s,f]=getColor(p.name);
    const tr=document.createElement('tr');
    const w=Math.min(100,p.mem*3).toFixed(1);
    tr.innerHTML=`
      <td><span class="dot" style="background:${f};border:0.5px solid ${s}"></span>${p.name}</td>
      <td><span class="badge">${p.pid}</span></td>
      <td>${p.mem.toFixed(1)}%</td>
      <td>${p.rss}</td>
      <td style="width:120px"><div class="bar-bg"><div class="bar-fg" style="width:${w}%;background:${s}"></div></div></td>
    `;
    tbody.appendChild(tr);
  }
}

fetchData();
setInterval(fetchData,2000);
</script>
</body>
</html>"""

cache = {"data": None, "ts": 0}

def get_vm_stat():
    try:
        r = subprocess.run(['vm_stat'], capture_output=True, text=True)
        lines = r.stdout.strip().split('\n')
        stats = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                stats[k.strip()] = int(v.strip().rstrip('.'))
        page = 16384
        free = stats.get('Pages free', 0) * page
        active = stats.get('Pages active', 0) * page
        inactive = stats.get('Pages inactive', 0) * page
        wired = stats.get('Pages wired down', 0) * page
        compressed = stats.get('Pages occupied by compressor', 0) * page
        total = free + active + inactive + wired + compressed
        used = active + wired + compressed
        return total / (1024**3), (used / total * 100) if total else 0
    except:
        return 8.0, 60.0

def get_procs():
    r = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    procs = []
    for line in r.stdout.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) < 11: continue
        try:
            mem = float(parts[3])
            if mem < 0.1: continue
            rss_kb = int(parts[5])
            rss = f"{rss_kb//1024}MB" if rss_kb > 1024 else f"{rss_kb}KB"
            name = parts[10].split('/')[-1][:20]
            procs.append({"pid": parts[1], "name": name, "mem": mem, "rss": rss})
        except: continue
    return sorted(procs, key=lambda x: -x['mem'])[:20]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML.encode())
        elif self.path == '/data':
            now = time.time()
            if now - cache['ts'] > 1.8 or not cache['data']:
                total_gb, used_pct = get_vm_stat()
                procs = get_procs()
                cache['data'] = json.dumps({"total_gb": total_gb, "used_pct": used_pct, "procs": procs})
                cache['ts'] = now
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(cache['data'].encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    port = 8765
    print(f"메모리 시각화 서버 시작!")
    print(f"브라우저에서 열기: http://localhost:{port}")
    print(f"종료: Ctrl+C\n")
    import webbrowser
    threading.Timer(0.5, lambda: webbrowser.open(f'http://localhost:{port}')).start()
    HTTPServer(('localhost', port), Handler).serve_forever()
