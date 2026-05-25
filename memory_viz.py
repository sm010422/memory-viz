#!/usr/bin/env python3
import subprocess, json, time, threading, re
from http.server import HTTPServer, BaseHTTPRequestHandler

REGION_COLORS = {
    "__TEXT":       ("#5BA8F0", "#0e2035", "실행 코드 (읽기전용)"),
    "__DATA":       ("#E8A030", "#2a1c06", "초기화된 전역 데이터"),
    "__DATA_CONST": ("#C09030", "#221808", "읽기전용 상수 데이터"),
    "__LINKEDIT":   ("#4a4a5a", "#1a1a20", "링커/심볼 메타데이터"),
    "MALLOC":       ("#2DC98E", "#092e1f", "힙 (malloc 영역)"),
    "Stack":        ("#E87BAA", "#2a0f1c", "스택 (함수 호출)"),
    "STACK":        ("#E87BAA", "#2a0f1c", "스택 (함수 호출)"),
    "__OBJC":       ("#8B7EE8", "#141028", "Objective-C 메타데이터"),
    "dyld":         ("#F07850", "#2a1108", "동적 링커"),
    "default":      ("#555566", "#1a1a22", "기타"),
}

cache = {"overview": None, "ts_ov": 0, "vmmap": {}}

def get_vm_stat():
    try:
        r = subprocess.run(["vm_stat"], capture_output=True, text=True)
        stats = {}
        for line in r.stdout.strip().split("\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                stats[k.strip()] = int(v.strip().rstrip("."))
        pg = 16384
        fp=stats.get("Pages free",0); ap=stats.get("Pages active",0)
        ip=stats.get("Pages inactive",0); wp=stats.get("Pages wired down",0)
        cp=stats.get("Pages occupied by compressor",0)
        total=fp+ap+ip+wp+cp
        return {"total_gb":round((total*pg)/1024**3,2),
                "used_pct":round((ap+wp+cp)/total*100,2) if total else 0,
                "segments":{"wired":round(wp/total,4)if total else 0,
                            "active":round(ap/total,4)if total else 0,
                            "inactive":round(ip/total,4)if total else 0,
                            "compressed":round(cp/total,4)if total else 0}}
    except: return {"total_gb":8.0,"used_pct":60.0,"segments":{}}

def get_procs():
    r = subprocess.run(["ps","aux"], capture_output=True, text=True)
    procs = []
    for line in r.stdout.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts)<11: continue
        try:
            mem=float(parts[3])
            if mem<0.1: continue
            rss_kb=int(parts[5])
            rss=f"{rss_kb//1024}MB" if rss_kb>1024 else f"{rss_kb}KB"
            name=parts[10].split("/")[-1][:24]
            procs.append({"pid":parts[1],"name":name,"mem":mem,"rss":rss,"cpu":parts[2]})
        except: continue
    return sorted(procs,key=lambda x:-x["mem"])[:20]

def get_vmmap(pid):
    try:
        r = subprocess.run(["vmmap","--wide",str(pid)],
                           capture_output=True,text=True,timeout=15)
        pat = re.compile(
            r"^([A-Za-z_][\w\-\. /]*?)\s{2,}([0-9a-f]+)-([0-9a-f]+)\s+"
            r"\[\s*([\d\.]+[KMG]?)\s+([\d\.]+[KMG]?)",re.M)
        regions=[]
        for m in pat.finditer(r.stdout):
            rtype,sh,eh,vs,rs=m.groups()
            rtype=rtype.strip()
            start=int(sh,16); end=int(eh,16)
            if end<=start: continue
            def psz(s):
                s=s.strip()
                if s.endswith("G"): return float(s[:-1])*1024**3
                if s.endswith("M"): return float(s[:-1])*1024**2
                if s.endswith("K"): return float(s[:-1])*1024
                return float(s)
            vsize=int(psz(vs)); rsize=int(psz(rs))
            if vsize==0: continue
            ck="default"
            for k in REGION_COLORS:
                if rtype.startswith(k): ck=k; break
            regions.append({"type":rtype,"start":start,"end":end,
                "startH":f"0x{sh.upper()}","endH":f"0x{eh.upper()}",
                "vsize":vsize,"rsize":rsize,"vsizeH":vs.strip(),"rsizeH":rs.strip(),
                "color":REGION_COLORS[ck][0],"bg":REGION_COLORS[ck][1],
                "desc":REGION_COLORS[ck][2],"key":ck})
        if not regions: return {"error":"vmmap 결과 없음 (sudo 로 실행해보세요)"}
        amin=min(r["start"] for r in regions)
        amax=max(r["end"]   for r in regions)
        span=amax-amin or 1
        for reg in regions:
            reg["pct_start"]=round((reg["start"]-amin)/span*100,4)
            reg["pct_end"]  =round((reg["end"]  -amin)/span*100,4)
        return {"regions":regions,
                "addr_min":f"0x{amin:016X}","addr_max":f"0x{amax:016X}",
                "total_virt":sum(r["vsize"] for r in regions),
                "total_rss": sum(r["rsize"] for r in regions)}
    except subprocess.TimeoutExpired: return {"error":"vmmap 시간 초과"}
    except Exception as e: return {"error":str(e)}

HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>메모리 실시간 시각화</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,sans-serif;background:#0e0e10;color:#e2e2e6;padding:16px;min-height:100vh}
h2{font-size:15px;font-weight:500;color:#aaa;margin-bottom:10px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px}
.stat{background:#1a1a1f;border:0.5px solid #2e2e38;border-radius:10px;padding:10px;text-align:center}
.stat-val{font-size:20px;font-weight:500}
.stat-lbl{font-size:11px;color:#555;margin-top:2px}
.panel{background:#1a1a1f;border:0.5px solid #2e2e38;border-radius:12px;overflow:hidden;margin-bottom:10px}
.ph{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:0.5px solid #2e2e38;background:#141418;font-size:12px;color:#666}
.ph .tip{color:#888;min-width:240px;text-align:right;font-size:11px}
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{padding:6px 12px;text-align:left;border-bottom:0.5px solid #222228}
th{font-size:11px;color:#555;font-weight:400;background:#141418}
.badge{font-size:10px;padding:1px 5px;border-radius:3px;background:#222;color:#666;border:0.5px solid #333}
.bar-bg{background:#222228;border-radius:2px;height:6px;width:80px}
.bar-fg{height:6px;border-radius:2px}
.dot{width:9px;height:9px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:middle}
.btn{font-size:11px;padding:3px 9px;border-radius:5px;border:0.5px solid #3e3e4e;background:#1e1e28;color:#aaa;cursor:pointer}
.btn:hover{background:#2e2e3e;color:#ddd}
.btn.active{border-color:#5BA8F0;color:#5BA8F0;background:#0e2035}
#status{font-size:11px}

/* vmmap 패널 */
.vmmap-wrap{padding:12px}
.addr-bar-wrap{display:flex;gap:8px;align-items:stretch;margin-bottom:10px}
.addr-labels{display:flex;flex-direction:column;justify-content:space-between;font-size:9px;font-family:monospace;color:#444;min-width:120px;text-align:right;padding-right:6px}
.addr-bar{flex:1;position:relative;background:#111114;border:0.5px solid #2e2e38;border-radius:6px;overflow:hidden;min-height:480px}
.addr-region{position:absolute;left:0;right:0;min-height:2px;display:flex;align-items:center;padding:0 6px;overflow:hidden;cursor:default}
.addr-region span{font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:monospace}
.region-table{width:100%;border-collapse:collapse;font-size:11px}
.region-table td,.region-table th{padding:4px 8px;border-bottom:0.5px solid #1e1e24;font-family:monospace}
.region-table th{color:#555;font-weight:400;background:#141418;font-family:sans-serif}
.legend-row{display:flex;flex-wrap:wrap;gap:8px;padding:8px 12px;border-top:0.5px solid #222}
.li{display:flex;align-items:center;gap:4px;font-size:11px;color:#666}
.ld{width:10px;height:10px;border-radius:2px}
.no-data{padding:20px;text-align:center;color:#555;font-size:13px}
.tab-bar{display:flex;gap:6px;padding:8px 12px;border-bottom:0.5px solid #2e2e38;background:#141418}
</style>
</head>
<body>
<div style="display:flex;align-items:baseline;gap:10px;margin-bottom:12px">
  <span style="font-size:16px;font-weight:500">메모리 시각화</span>
  <span id="status" style="font-size:11px;color:#2DC98E">● 실시간</span>
</div>

<div class="stats">
  <div class="stat"><div class="stat-val" id="s-total">—</div><div class="stat-lbl">총 메모리</div></div>
  <div class="stat"><div class="stat-val" id="s-used">—</div><div class="stat-lbl">사용 중</div></div>
  <div class="stat"><div class="stat-val" id="s-free">—</div><div class="stat-lbl">여유</div></div>
  <div class="stat"><div class="stat-val" id="s-procs">—</div><div class="stat-lbl">프로세스</div></div>
</div>

<div class="panel">
  <div class="ph">
    <span>프로세스 목록 — 행 클릭 시 가상 메모리 맵 상세 보기</span>
    <span class="tip" id="tip">프로세스를 클릭하면 실제 메모리 주소를 볼 수 있어요</span>
  </div>
  <table>
    <thead><tr><th>프로세스</th><th>PID</th><th>메모리%</th><th>RSS</th><th>CPU%</th><th></th></tr></thead>
    <tbody id="proc-tbody"></tbody>
  </table>
</div>

<div class="panel" id="vmmap-panel" style="display:none">
  <div class="ph">
    <span id="vmmap-title">가상 메모리 맵</span>
    <span class="tip" id="vmmap-tip">영역에 마우스를 올리면 주소 정보</span>
  </div>
  <div class="tab-bar">
    <button class="btn active" onclick="setView('bar')">주소 바</button>
    <button class="btn" onclick="setView('table')">테이블</button>
  </div>
  <div class="vmmap-wrap" id="vmmap-content"><div class="no-data">로딩 중...</div></div>
  <div class="legend-row" id="vmmap-legend"></div>
</div>

<script>
const PALETTE={
  '__TEXT':       ['#5BA8F0','#0e2035'],
  '__DATA':       ['#E8A030','#2a1c06'],
  '__DATA_CONST': ['#C09030','#221808'],
  '__LINKEDIT':   ['#4a4a5a','#1a1a20'],
  'MALLOC':       ['#2DC98E','#092e1f'],
  'Stack':        ['#E87BAA','#2a0f1c'],
  'STACK':        ['#E87BAA','#2a0f1c'],
  '__OBJC':       ['#8B7EE8','#141028'],
  'dyld':         ['#F07850','#2a1108'],
  'default':      ['#555566','#1a1a22'],
};
const procColors={};let palIdx2=0;
const PAL2=[['#5BA8F0','#0e2035'],['#2DC98E','#092e1f'],['#E87BAA','#2a0f1c'],
  ['#E8A030','#2a1c06'],['#8B7EE8','#141028'],['#F07850','#2a1108'],
  ['#86C440','#182208'],['#F07070','#2a0e0e'],['#D06090','#280d1c'],['#4090D8','#0c1e38']];
function getProcColor(pid){if(!procColors[pid]){procColors[pid]=PAL2[palIdx2%PAL2.length];palIdx2++;}return procColors[pid];}

let selectedPid=null, currentView='bar', vmData=null;

function setView(v){
  currentView=v;
  document.querySelectorAll('.tab-bar .btn').forEach((b,i)=>{
    b.classList.toggle('active',['bar','table'][i]===v);
  });
  if(vmData) renderVmmap(vmData);
}

async function fetchOverview(){
  try{
    const d=await(await fetch('/overview')).json();
    document.getElementById('s-total').textContent=d.total_gb.toFixed(1)+'GB';
    document.getElementById('s-used').textContent=d.used_pct.toFixed(1)+'%';
    document.getElementById('s-free').textContent=(100-d.used_pct).toFixed(1)+'%';
    document.getElementById('s-procs').textContent=d.procs.length;
    renderProcs(d.procs);
    document.getElementById('status').textContent='● 실시간';
    document.getElementById('status').style.color='#2DC98E';
  }catch{
    document.getElementById('status').textContent='● 연결 끊김';
    document.getElementById('status').style.color='#F07070';
  }
}

function renderProcs(procs){
  const tbody=document.getElementById('proc-tbody');
  const rows=[];
  for(const p of procs){
    const[s,f]=getProcColor(p.pid);
    const w=Math.min(100,p.mem*3).toFixed(1);
    const sel=p.pid===selectedPid;
    rows.push(`<tr onclick="selectProc('${p.pid}','${p.name}')" style="cursor:pointer;background:${sel?'#1e2030':'transparent'};transition:background .15s">
      <td><span class="dot" style="background:${f};border:0.5px solid ${s}"></span>${p.name}</td>
      <td><span class="badge">${p.pid}</span></td>
      <td>${p.mem.toFixed(1)}%</td>
      <td>${p.rss}</td>
      <td style="color:#666">${p.cpu}%</td>
      <td><div class="bar-bg"><div class="bar-fg" style="width:${w}%;background:${s}"></div></div></td>
    </tr>`);
  }
  tbody.innerHTML=rows.join('');
}

async function selectProc(pid, name){
  selectedPid=pid;
  document.getElementById('vmmap-panel').style.display='block';
  document.getElementById('vmmap-title').textContent=`${name}  (PID ${pid})  가상 메모리 맵`;
  document.getElementById('vmmap-content').innerHTML='<div class="no-data">vmmap 실행 중... (수초 소요)</div>';
  document.getElementById('vmmap-legend').innerHTML='';
  fetchOverview();
  try{
    const d=await(await fetch(`/vmmap/${pid}`)).json();
    if(d.error){
      document.getElementById('vmmap-content').innerHTML=`<div class="no-data">${d.error}<br><br><span style="font-size:11px;color:#444">sudo python3 로 실행하면 더 많은 프로세스를 볼 수 있어요</span></div>`;
      return;
    }
    vmData=d;
    renderVmmap(d);
  }catch(e){
    document.getElementById('vmmap-content').innerHTML=`<div class="no-data">오류: ${e}</div>`;
  }
}

function renderVmmap(d){
  const tip=document.getElementById('vmmap-tip');

  if(currentView==='bar'){
    // 주소 바 뷰
    const barH=Math.max(480, d.regions.length*4);
    let regionsHtml='';
    for(const r of d.regions){
      const top=r.pct_start;
      const h=Math.max(2, r.pct_end - r.pct_start);
      const[s,bg]=PALETTE[r.key]||PALETTE['default'];
      regionsHtml+=`<div class="addr-region"
        style="top:${top}%;height:${h}%;background:${bg};border-top:1px solid ${s}66"
        onmouseenter="document.getElementById('vmmap-tip').textContent='${r.type.replace(/'/g,'`')}  ${r.startH} → ${r.endH}  virt=${r.vsizeH}  rss=${r.rsizeH}'"
        onmouseleave="document.getElementById('vmmap-tip').textContent='영역에 마우스를 올리면 주소 정보'">
        <span style="color:${s};font-size:9px">${r.type}</span>
      </div>`;
    }
    // 주소 레이블 (10단계)
    let labels='';
    for(let i=0;i<=10;i++){
      const pct=i*10;
      const span=BigInt('0x'+d.addr_max.slice(2))-BigInt('0x'+d.addr_min.slice(2));
      const addr=BigInt('0x'+d.addr_min.slice(2))+span*BigInt(pct)/100n;
      labels+=`<span>${'0x'+addr.toString(16).toUpperCase().padStart(10,'0')}</span>`;
    }
    document.getElementById('vmmap-content').innerHTML=`
      <div style="margin-bottom:8px;font-size:11px;color:#555;font-family:monospace">
        주소 범위: ${d.addr_min} → ${d.addr_max} &nbsp;|&nbsp; 
        가상: ${fmtBytes(d.total_virt)} &nbsp;|&nbsp; RSS: ${fmtBytes(d.total_rss)}
      </div>
      <div class="addr-bar-wrap">
        <div class="addr-labels" style="flex-direction:column-reverse">${labels}</div>
        <div class="addr-bar" style="height:${barH}px">${regionsHtml}</div>
      </div>`;
  } else {
    // 테이블 뷰 - 실제 주소값 표시
    const rows=d.regions.map(r=>{
      const[s,bg]=PALETTE[r.key]||PALETTE['default'];
      return `<tr>
        <td><span class="dot" style="background:${bg};border:0.5px solid ${s}"></span>${r.type}</td>
        <td style="color:#5BA8F0">${r.startH}</td>
        <td style="color:#E87BAA">${r.endH}</td>
        <td style="color:#aaa">${r.vsizeH}</td>
        <td style="color:#2DC98E">${r.rsizeH}</td>
        <td style="color:#666">${r.desc}</td>
      </tr>`;
    }).join('');
    document.getElementById('vmmap-content').innerHTML=`
      <div style="margin-bottom:8px;font-size:11px;color:#555;font-family:monospace;padding:0 4px">
        총 ${d.regions.length}개 영역 &nbsp;|&nbsp; 가상: ${fmtBytes(d.total_virt)} &nbsp;|&nbsp; RSS: ${fmtBytes(d.total_rss)}
      </div>
      <table class="region-table">
        <thead><tr><th>영역 타입</th><th>시작 주소</th><th>끝 주소</th><th>가상 크기</th><th>RSS</th><th>설명</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  // 범례
  const seen=new Set();
  let leg='';
  for(const r of d.regions){
    if(seen.has(r.key)) continue;
    seen.add(r.key);
    const[s,bg]=PALETTE[r.key]||PALETTE['default'];
    leg+=`<div class="li"><div class="ld" style="background:${bg};border:0.5px solid ${s}"></div><span>${r.key==='default'?'기타':r.key} — ${r.desc}</span></div>`;
  }
  document.getElementById('vmmap-legend').innerHTML=leg;
}

function fmtBytes(b){
  if(b>=1024**3) return (b/1024**3).toFixed(1)+'GB';
  if(b>=1024**2) return (b/1024**2).toFixed(1)+'MB';
  if(b>=1024)    return (b/1024).toFixed(1)+'KB';
  return b+'B';
}

fetchOverview();
setInterval(fetchOverview, 2000);
</script>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        if self.path=="/":
            self.reply(200,"text/html; charset=utf-8", HTML.encode())
        elif self.path=="/overview":
            now=time.time()
            if now-cache["ts_ov"]>1.8 or not cache["overview"]:
                vm=get_vm_stat(); vm["procs"]=get_procs()
                cache["overview"]=json.dumps(vm); cache["ts_ov"]=now
            self.reply(200,"application/json",cache["overview"].encode())
        elif self.path.startswith("/vmmap/"):
            pid=self.path.split("/")[-1]
            if pid not in cache["vmmap"] or time.time()-cache["vmmap"][pid]["ts"]>10:
                data=get_vmmap(pid)
                cache["vmmap"][pid]={"data":json.dumps(data),"ts":time.time()}
            self.reply(200,"application/json",cache["vmmap"][pid]["data"].encode())
        else: self.reply(404,"text/plain",b"not found")
    def reply(self,code,ct,body):
        self.send_response(code)
        self.send_header("Content-Type",ct); self.end_headers(); self.wfile.write(body)

if __name__=="__main__":
    port=8765
    print(f"시작: http://localhost:{port}")
    print("종료: Ctrl+C")
    import webbrowser
    threading.Timer(0.6,lambda:webbrowser.open(f"http://localhost:{port}")).start()
    HTTPServer(("localhost",port),Handler).serve_forever()
