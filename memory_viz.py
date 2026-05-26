#!/usr/bin/env python3
import subprocess, json, time, threading, re
from http.server import HTTPServer, BaseHTTPRequestHandler

cache = {"ov": None, "ts_ov": 0, "vm": {}, "ts_vm": {}}

SEG_COLORS = {
    "__TEXT":        {"stroke": "#5BA8F0", "fill": "#0a1828", "label": "코드"},
    "__DATA":        {"stroke": "#E8A030", "fill": "#221800", "label": "데이터"},
    "__DATA_CONST":  {"stroke": "#C09030", "fill": "#1c1400", "label": "상수"},
    "__LINKEDIT":    {"stroke": "#606070", "fill": "#141418", "label": "링커"},
    "__OBJC":        {"stroke": "#8B7EE8", "fill": "#100e24", "label": "ObjC"},
    "MALLOC_LARGE":  {"stroke": "#2DC98E", "fill": "#061a10", "label": "힙(large)"},
    "MALLOC_SMALL":  {"stroke": "#28B07A", "fill": "#061610", "label": "힙(small)"},
    "MALLOC_TINY":   {"stroke": "#22906A", "fill": "#051210", "label": "힙(tiny)"},
    "MALLOC":        {"stroke": "#2DC98E", "fill": "#061a10", "label": "힙"},
    "Stack":         {"stroke": "#E87BAA", "fill": "#240a18", "label": "스택"},
    "STACK":         {"stroke": "#E87BAA", "fill": "#240a18", "label": "스택"},
    "dyld":          {"stroke": "#F07850", "fill": "#200e04", "label": "동적링커"},
    "mapped":        {"stroke": "#5580A0", "fill": "#0c1418", "label": "mapped"},
    "VM_ALLOCATE":   {"stroke": "#404858", "fill": "#0e1014", "label": "VM할당"},
    "__UNICODE":     {"stroke": "#806888", "fill": "#140e18", "label": "유니코드"},
    "default":       {"stroke": "#3a3a48", "fill": "#101014", "label": "기타"},
}

def get_color(rtype):
    for k in SEG_COLORS:
        if rtype.startswith(k):
            return SEG_COLORS[k]
    return SEG_COLORS["default"]

def vm_stat():
    try:
        r = subprocess.run(["vm_stat"], capture_output=True, text=True)
        s = {}
        for line in r.stdout.strip().split("\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                s[k.strip()] = int(v.strip().rstrip("."))
        pg = 16384
        fp=s.get("Pages free",0); ap=s.get("Pages active",0)
        ip=s.get("Pages inactive",0); wp=s.get("Pages wired down",0)
        cp=s.get("Pages occupied by compressor",0)
        t = fp+ap+ip+wp+cp
        return {
            "total_gb": round(t*pg/1024**3, 1),
            "used_pct": round((ap+wp+cp)/t*100, 1) if t else 0,
            "seg": {
                "wired":      round(wp/t, 4) if t else 0,
                "active":     round(ap/t, 4) if t else 0,
                "inactive":   round(ip/t, 4) if t else 0,
                "compressed": round(cp/t, 4) if t else 0,
                "free":       round(fp/t, 4) if t else 0,
            }
        }
    except:
        return {"total_gb": 8.0, "used_pct": 60.0, "seg": {}}

def get_procs():
    r = subprocess.run(["ps","aux"], capture_output=True, text=True)
    out = []
    for line in r.stdout.strip().split("\n")[1:]:
        p = line.split()
        if len(p) < 11: continue
        try:
            mem = float(p[3])
            if mem < 0.1: continue
            rss = int(p[5])
            out.append({"pid": p[1], "name": p[10].split("/")[-1][:22],
                        "mem": mem, "rss": rss, "cpu": p[2]})
        except: continue
    return sorted(out, key=lambda x: -x["mem"])[:20]

def get_vmmap(pid):
    try:
        r = subprocess.run(["vmmap", "--wide", str(pid)],
                           capture_output=True, text=True, timeout=15)
        pat = re.compile(
            r"^([A-Za-z_][\w\-\. /]*?)\s{2,}([0-9a-f]+)-([0-9a-f]+)\s+"
            r"\[\s*([\d\.]+[KMG]?)\s+([\d\.]+[KMG]?)\s+([\d\.]+[KMG]?)",
            re.M)

        def parse_size(s):
            s = s.strip()
            if s.endswith("G"): return float(s[:-1]) * 1024**3
            if s.endswith("M"): return float(s[:-1]) * 1024**2
            if s.endswith("K"): return float(s[:-1]) * 1024
            return float(s)

        regions = []
        for m in pat.finditer(r.stdout):
            rtype, sh, eh, vs, rss_s, dirty_s = m.groups()
            rtype = rtype.strip()
            start = int(sh, 16); end = int(eh, 16)
            if end <= start: continue
            vsize = int(parse_size(vs))
            rsize = int(parse_size(rss_s))
            if vsize == 0: continue
            c = get_color(rtype)
            regions.append({
                "type":    rtype,
                "startH":  f"0x{sh.upper().zfill(12)}",
                "endH":    f"0x{eh.upper().zfill(12)}",
                "start":   start,
                "end":     end,
                "vsize":   vsize,
                "rsize":   rsize,
                "vsizeH":  vs.strip(),
                "rsizeH":  rss_s.strip(),
                "stroke":  c["stroke"],
                "fill":    c["fill"],
                "label":   c["label"],
            })

        if not regions:
            return {"error": "결과 없음 — sudo 로 실행해보세요"}

        amin = min(r["start"] for r in regions)
        amax = max(r["end"]   for r in regions)
        span = amax - amin or 1

        for rg in regions:
            rg["pct_start"] = round((rg["start"] - amin) / span * 100, 5)
            rg["pct_end"]   = round((rg["end"]   - amin) / span * 100, 5)
            rg["pct_h"]     = max(0.3, rg["pct_end"] - rg["pct_start"])

        return {
            "regions":    regions,
            "amin":       f"0x{amin:012X}",
            "amax":       f"0x{amax:012X}",
            "total_virt": sum(r["vsize"] for r in regions),
            "total_rss":  sum(r["rsize"] for r in regions),
            "count":      len(regions),
            "ts":         round(time.time()),
        }
    except subprocess.TimeoutExpired:
        return {"error": "vmmap 시간 초과"}
    except Exception as e:
        return {"error": str(e)}

HTML = """<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><title>메모리 시각화</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,sans-serif;background:#0a0a0c;color:#c8c8d0;padding:16px}
.row{display:flex;gap:8px;margin-bottom:8px}
.stat{background:#141416;border:0.5px solid #242430;border-radius:8px;padding:10px 14px;flex:1}
.stat-v{font-size:20px;font-weight:500;letter-spacing:-.5px}
.stat-l{font-size:11px;color:#3a3a48;margin-top:2px}
.seg-wrap{background:#141416;border:0.5px solid #242430;border-radius:8px;padding:10px 14px;margin-bottom:8px}
.seg-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;gap:1px;margin:6px 0}
.seg-row{display:flex;gap:12px;flex-wrap:wrap}
.seg-li{display:flex;align-items:center;gap:4px;font-size:11px;color:#3a3a48}
.seg-dot{width:7px;height:7px;border-radius:1px}
/* 메인 2단 레이아웃 */
.main{display:flex;gap:8px;align-items:flex-start}
.left{flex:0 0 340px}
.right{flex:1;min-width:0}
/* 프로세스 목록 */
.panel{background:#141416;border:0.5px solid #242430;border-radius:8px;overflow:hidden;margin-bottom:8px}
.ph{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:0.5px solid #1e1e28;background:#0e0e12;font-size:11px;color:#3a3a48}
table{width:100%;border-collapse:collapse}
td,th{padding:6px 10px;text-align:left;border-bottom:0.5px solid #181820;font-size:11px}
th{color:#3a3a48;font-weight:400;background:#0e0e12;font-size:10px}
tr.pr{cursor:pointer;transition:background .1s}
tr.pr:hover{background:#1a1a22}
tr.pr.sel{background:#0e1828;border-left:2px solid #5BA8F0}
.badge{font-size:9px;padding:1px 5px;border-radius:3px;background:#1a1a22;color:#444;border:0.5px solid #242430;font-family:monospace}
.dot{width:8px;height:8px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:middle;flex-shrink:0}
.bar-bg{background:#1a1a22;border-radius:2px;height:4px;width:60px}
.bar-fg{height:4px;border-radius:2px}
/* vmmap 주소 뷰 */
.vm-wrap{background:#141416;border:0.5px solid #242430;border-radius:8px;overflow:hidden}
.vm-hd{padding:9px 12px;border-bottom:0.5px solid #1e1e28;background:#0e0e12;font-size:11px;color:#3a3a48;display:flex;justify-content:space-between}
.vm-hd-r{color:#444;min-width:200px;text-align:right;font-size:10px;font-family:monospace}
.vm-body{display:flex;gap:0;height:640px}
/* 주소 축 */
.axis{width:116px;flex-shrink:0;display:flex;flex-direction:column-reverse;justify-content:space-between;padding:8px 8px 8px 4px;border-right:0.5px solid #1e1e28;background:#0e0e12}
.axis-lbl{font-size:9px;font-family:monospace;color:#2a2a38;text-align:right;line-height:1}
/* 주소 바 */
.addr-col{flex:1;position:relative;background:#0c0c10;overflow:hidden}
.rgn{position:absolute;left:0;right:0;min-height:1px;cursor:default;transition:filter .1s;display:flex;align-items:center;padding:0 6px;overflow:hidden}
.rgn:hover{filter:brightness(1.8)!important;z-index:10}
.rgn-lbl{font-size:8.5px;font-family:monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;pointer-events:none}
/* 오른쪽 정보 */
.info-col{width:180px;flex-shrink:0;border-left:0.5px solid #1e1e28;background:#0e0e12;overflow-y:auto;padding:8px}
.info-title{font-size:10px;color:#3a3a48;margin-bottom:6px}
.info-row{margin-bottom:10px;padding-bottom:10px;border-bottom:0.5px solid #181820}
.info-row:last-child{border-bottom:none}
.info-k{font-size:9px;color:#3a3a48;margin-bottom:2px}
.info-v{font-size:10px;font-family:monospace;color:#a0a0b0;word-break:break-all}
.info-v.addr{color:#5BA8F0}
.info-v.rss{color:#2DC98E}
.no-sel{padding:20px 10px;font-size:11px;color:#2a2a38;line-height:1.8;text-align:center}
/* 테이블 뷰 */
.rtable{width:100%;border-collapse:collapse;font-size:10px}
.rtable td,.rtable th{padding:4px 8px;border-bottom:0.5px solid #181820;font-family:monospace}
.rtable th{color:#3a3a48;font-weight:400;background:#0e0e12;font-family:sans-serif;font-size:10px}
.tab-bar{display:flex;gap:4px;padding:6px 10px;border-bottom:0.5px solid #1e1e28;background:#0e0e12}
.tb{font-size:10px;padding:2px 8px;border-radius:4px;border:0.5px solid #2a2a38;background:transparent;color:#444;cursor:pointer}
.tb:hover{color:#888}
.tb.on{border-color:#5BA8F0;color:#5BA8F0;background:#061424}
.upd{font-size:9px;color:#2a2a38;font-family:monospace;padding:4px 10px;border-top:0.5px solid #181820}
#status{font-size:10px}
</style></head><body>

<div class="row" style="margin-bottom:8px;align-items:center">
  <span style="font-size:14px;font-weight:500;color:#a0a0b0;margin-right:4px">메모리 시각화</span>
  <span id="status" style="color:#2DC98E;font-size:10px">● 실시간</span>
</div>

<div class="row">
  <div class="stat"><div class="stat-v" id="s-total">—</div><div class="stat-l">총 메모리</div></div>
  <div class="stat"><div class="stat-v" id="s-used">—</div><div class="stat-l">사용 중</div></div>
  <div class="stat"><div class="stat-v" id="s-free">—</div><div class="stat-l">여유</div></div>
  <div class="stat"><div class="stat-v" id="s-procs">—</div><div class="stat-l">프로세스</div></div>
</div>

<div class="seg-wrap">
  <div style="font-size:10px;color:#3a3a48;margin-bottom:4px">물리 메모리 구성</div>
  <div class="seg-bar" id="seg-bar"></div>
  <div class="seg-row" id="seg-row"></div>
</div>

<div class="main">
  <!-- 왼쪽: 프로세스 목록 -->
  <div class="left">
    <div class="panel">
      <div class="ph"><span>프로세스 목록</span><span>클릭 → 주소 공간 보기</span></div>
      <table><thead><tr><th>이름</th><th>PID</th><th>MEM</th><th>RSS</th><th></th></tr></thead>
      <tbody id="ptbody"></tbody></table>
    </div>
  </div>

  <!-- 오른쪽: 가상 주소 공간 -->
  <div class="right">
    <div class="vm-wrap">
      <div class="vm-hd">
        <span id="vm-title" style="color:#888">← 프로세스를 선택하면 실제 가상 주소 공간을 실시간으로 표시합니다</span>
        <span class="vm-hd-r" id="vm-tip"></span>
      </div>
      <div class="tab-bar" id="tab-bar" style="display:none">
        <button class="tb on" onclick="setV('bar')">주소 바</button>
        <button class="tb" onclick="setV('tbl')">테이블</button>
      </div>
      <div class="vm-body" id="vm-body">
        <div style="width:100%;display:flex;align-items:center;justify-content:center;color:#2a2a38;font-size:12px">
          프로세스를 클릭하세요
        </div>
      </div>
      <div class="upd" id="vm-upd"></div>
    </div>
  </div>
</div>

<script>
const PAL=[['#5BA8F0','#061424'],['#2DC98E','#061810'],['#E87BAA','#200814'],
  ['#E8A030','#201400'],['#8B7EE8','#0e0c24'],['#F07850','#200c04'],
  ['#86C440','#101800'],['#F07070','#200808'],['#D06090','#200418'],
  ['#4090D8','#081428'],['#C09030','#181000'],['#2BBFA0','#061e18']];
const pclr={};let pi=0;
function pc(pid){if(!pclr[pid]){pclr[pid]=PAL[pi%PAL.length];pi++;}return pclr[pid];}

let selPid=null, selName='', curV='bar', vmData=null, lastProcs=[];

// ── 세그먼트 바
function drawSeg(seg){
  const defs=[['wired','#3a1e58','wired'],['active','#0e2818','active'],
    ['inactive','#0e1e0e','inactive'],['compressed','#2a2200','comp'],['free','#1e1e28','free']];
  let bar='',row='';
  for(const[k,c,l] of defs){
    const p=(seg[k]||0)*100;
    if(p<0.3)continue;
    bar+=`<div style="flex:${p};background:${c};min-width:2px"></div>`;
    row+=`<div class="seg-li"><div class="seg-dot" style="background:${c}"></div><span>${l} ${p.toFixed(1)}%</span></div>`;
  }
  document.getElementById('seg-bar').innerHTML=bar;
  document.getElementById('seg-row').innerHTML=row;
}

// ── 프로세스 테이블
function drawProcs(procs){
  document.getElementById('ptbody').innerHTML=procs.map(p=>{
    const[s,f]=pc(p.pid);
    const w=Math.min(100,p.mem*3).toFixed(1);
    const sel=p.pid===selPid;
    const rss=p.rss>=1024?`${Math.round(p.rss/1024)}MB`:`${p.rss}KB`;
    return `<tr class="pr${sel?' sel':''}" onclick="clickProc('${p.pid}','${p.name.replace(/'/g,'`')}')">
      <td><span class="dot" style="background:${f};border:0.5px solid ${s}30"></span>${p.name}</td>
      <td><span class="badge">${p.pid}</span></td>
      <td>${p.mem.toFixed(1)}%</td>
      <td style="color:#666">${rss}</td>
      <td><div class="bar-bg"><div class="bar-fg" style="width:${w}%;background:${s}"></div></div></td>
    </tr>`;
  }).join('');
}

// ── 프로세스 클릭
async function clickProc(pid, name){
  selPid=pid; selName=name;
  drawProcs(lastProcs);
  document.getElementById('vm-title').textContent=`${name}  PID ${pid}`;
  document.getElementById('vm-title').style.color='#a0a0b0';
  document.getElementById('tab-bar').style.display='flex';
  showLoading();
  await loadVmmap(pid);
}

function showLoading(){
  document.getElementById('vm-body').innerHTML=
    `<div style="width:100%;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:8px;color:#2a2a38">
      <span style="font-size:12px">vmmap 로딩 중...</span>
      <span style="font-size:10px">프로세스 크기에 따라 수초 소요</span>
    </div>`;
}

async function loadVmmap(pid){
  try{
    const d=await(await fetch('/vmmap/'+pid)).json();
    if(d.error){
      document.getElementById('vm-body').innerHTML=
        `<div style="width:100%;display:flex;align-items:center;justify-content:center;color:#2a2a38;font-size:12px;flex-direction:column;gap:6px">
          <span>${d.error}</span>
          <span style="font-size:10px">sudo python3 로 실행하면 다른 프로세스도 볼 수 있어요</span>
        </div>`;
      return;
    }
    vmData=d;
    renderVM(d);
    const ts=new Date(d.ts*1000).toLocaleTimeString('ko-KR');
    document.getElementById('vm-upd').textContent=`마지막 갱신: ${ts}  |  ${d.count}개 영역  |  가상 ${fmtB(d.total_virt)}  |  RSS ${fmtB(d.total_rss)}`;
  }catch(e){
    document.getElementById('vm-body').innerHTML=
      `<div style="width:100%;display:flex;align-items:center;justify-content:center;color:#2a2a38;font-size:11px">${e}</div>`;
  }
}

function setV(v){
  curV=v;
  document.querySelectorAll('.tb').forEach((b,i)=>b.classList.toggle('on',['bar','tbl'][i]===v));
  if(vmData)renderVM(vmData);
}

function renderVM(d){
  if(curV==='bar') renderBar(d);
  else renderTable(d);
}

function renderBar(d){
  // 주소 축 레이블 (12단계)
  const mn=BigInt('0x'+d.amin.slice(2));
  const mx=BigInt('0x'+d.amax.slice(2));
  let axis='';
  for(let i=12;i>=0;i--){
    const a=mn+(mx-mn)*BigInt(i)/12n;
    axis+=`<div class="axis-lbl">0x${a.toString(16).toUpperCase().padStart(12,'0')}</div>`;
  }

  // 영역들
  let rgns='';
  for(const r of d.regions){
    const h=Math.max(0.4, r.pct_h);
    rgns+=`<div class="rgn"
      style="top:${r.pct_start}%;height:${h}%;background:${r.fill};border-top:1px solid ${r.stroke}44"
      onmouseenter="hoverRgn(${JSON.stringify(r).replace(/"/g,'&quot;')})"
      onmouseleave="clearHover()">
      <span class="rgn-lbl" style="color:${r.stroke}">${r.type}</span>
    </div>`;
  }

  document.getElementById('vm-body').innerHTML=`
    <div class="axis">${axis}</div>
    <div class="addr-col">${rgns}</div>
    <div class="info-col" id="info-col">
      <div class="info-title">영역 정보</div>
      <div style="font-size:10px;color:#2a2a38;line-height:1.8">영역에<br>마우스를<br>올려보세요</div>
    </div>`;
}

function hoverRgn(r){
  document.getElementById('vm-tip').textContent=`${r.type}  ${r.startH} → ${r.endH}`;
  const ic=document.getElementById('info-col');
  if(!ic)return;
  ic.innerHTML=`<div class="info-title" style="color:${r.stroke}">${r.type}</div>
    <div class="info-row">
      <div class="info-k">시작 주소</div>
      <div class="info-v addr">${r.startH}</div>
    </div>
    <div class="info-row">
      <div class="info-k">끝 주소</div>
      <div class="info-v addr">${r.endH}</div>
    </div>
    <div class="info-row">
      <div class="info-k">가상 크기</div>
      <div class="info-v">${r.vsizeH}</div>
    </div>
    <div class="info-row">
      <div class="info-k">RSS (실제 점유)</div>
      <div class="info-v rss">${r.rsizeH}</div>
    </div>
    <div class="info-row">
      <div class="info-k">종류</div>
      <div class="info-v" style="color:#888">${r.label}</div>
    </div>`;
}
function clearHover(){
  document.getElementById('vm-tip').textContent='';
}

function renderTable(d){
  const rows=d.regions.map(r=>`<tr>
    <td style="color:${r.stroke}">${r.type}</td>
    <td style="color:#5BA8F0">${r.startH}</td>
    <td style="color:#c060a0">${r.endH}</td>
    <td style="color:#888">${r.vsizeH}</td>
    <td style="color:#2DC98E">${r.rsizeH}</td>
    <td style="color:#555;font-family:sans-serif">${r.label}</td>
  </tr>`).join('');
  document.getElementById('vm-body').innerHTML=`
    <div style="flex:1;overflow:auto">
      <table class="rtable">
        <thead><tr><th>타입</th><th>시작 주소</th><th>끝 주소</th><th>가상</th><th>RSS</th><th>설명</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function fmtB(b){
  if(b>=1024**3)return(b/1024**3).toFixed(1)+'GB';
  if(b>=1024**2)return(b/1024**2).toFixed(1)+'MB';
  if(b>=1024)return(b/1024).toFixed(1)+'KB';
  return b+'B';
}

// ── 폴링
async function tickOv(){
  try{
    const d=await(await fetch('/overview')).json();
    document.getElementById('s-total').textContent=d.total_gb+'GB';
    document.getElementById('s-used').textContent=d.used_pct+'%';
    document.getElementById('s-free').textContent=(100-d.used_pct).toFixed(1)+'%';
    document.getElementById('s-procs').textContent=d.procs.length;
    drawSeg(d.seg);
    lastProcs=d.procs;
    drawProcs(d.procs);
    document.getElementById('status').textContent='● 실시간';
    document.getElementById('status').style.color='#2DC98E';
  }catch{
    document.getElementById('status').textContent='● 연결 끊김';
    document.getElementById('status').style.color='#E87BAA';
  }
}

// vmmap은 별도 주기 (4초)
let vmPending=false;
async function tickVm(){
  if(!selPid||vmPending)return;
  vmPending=true;
  try{ await loadVmmap(selPid); }
  finally{ vmPending=false; }
}

tickOv();
setInterval(tickOv, 2000);
setInterval(tickVm, 4000);
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == '/':
            self.reply(200, 'text/html; charset=utf-8', HTML.encode())
        elif self.path == '/overview':
            now = time.time()
            if now - cache['ts_ov'] > 1.8 or not cache['ov']:
                v = vm_stat(); v['procs'] = get_procs()
                cache['ov'] = json.dumps(v); cache['ts_ov'] = now
            self.reply(200, 'application/json', cache['ov'].encode())
        elif self.path.startswith('/vmmap/'):
            pid = self.path.split('/')[-1]
            now = time.time()
            if pid not in cache['ts_vm'] or now - cache['ts_vm'].get(pid,0) > 3.5:
                data = get_vmmap(pid)
                cache['vm'][pid] = json.dumps(data)
                cache['ts_vm'][pid] = now
            self.reply(200, 'application/json', cache['vm'][pid].encode())
        else:
            self.reply(404, 'text/plain', b'')

    def reply(self, code, ct, body):
        self.send_response(code)
        self.send_header('Content-Type', ct)
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    port = 8765
    print(f"시작: http://localhost:{port}")
    print("종료: Ctrl+C")
    import webbrowser
    threading.Timer(0.5, lambda: webbrowser.open(f'http://localhost:{port}')).start()
    HTTPServer(('localhost', port), Handler).serve_forever()
