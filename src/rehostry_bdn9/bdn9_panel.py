#!/usr/bin/env python3
# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live web panel for the rehosted Keebio BDN9 rev2 and its attack.

One browser tab that boots the real rehosted firmware, drives it over the
modelled USB bus, and shows -- live -- the firmware's own bytes next to the
prediction that was committed before it was ever booted.

Transport is plain ``/state`` POLLING, never Server-Sent Events: SSE is buffered
by tunnelling proxies, so an EventSource panel is a permanently blank page
remotely while it works perfectly on localhost (playbook 2.5).

    rehostry-bdn9-panel          # or: python3 -m rehostry_bdn9.bdn9_panel
"""
from __future__ import annotations

import argparse
import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import attack, spawn

_LOCK = threading.Lock()
_STATE = {
    "busy": False,
    "stage": "idle",
    "log": [],
    "result": None,
    "started": None,
}
ARGS: argparse.Namespace


def _on_stage(name, **data):
    with _LOCK:
        _STATE["stage"] = name
        _STATE["log"].append({"stage": name,
                              "data": {k: str(v) for k, v in data.items()}})
        _STATE["log"] = _STATE["log"][-120:]


def _run(control: bool) -> None:
    with _LOCK:
        _STATE.update(busy=True, stage="booting", log=[], result=None,
                      started=time.time())
    try:
        res = attack.run_attack(on_stage=_on_stage, port=ARGS.bridge_port,
                                control=control)
    except Exception as exc:  # noqa: BLE001
        res = {"error": repr(exc), "booted": False, "landed": False,
               "milestone": "M0"}
    with _LOCK:
        _STATE.update(busy=False, stage="done", result=res)


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Keebio BDN9 rev2 &mdash; rehosted</title>
<style>
 :root{--bg:#12141a;--fg:#e6e8ee;--dim:#98a0b3;--ok:#4ec9a0;--bad:#ff6b6b;
       --card:#1a1d26;--line:#2a2f3d;--acc:#7aa2f7}
 body{background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,
      "SF Mono",Menlo,monospace;margin:0;padding:20px}
 h1{font-size:20px;margin:0 0 4px} h2{font-size:14px;color:var(--acc);
   margin:18px 0 6px;text-transform:uppercase;letter-spacing:.08em}
 .card{background:var(--card);border:1px solid var(--line);border-radius:8px;
   padding:12px 14px;margin:10px 0}
 .brief summary{cursor:pointer;color:var(--acc);font-weight:600}
 .brief b{color:var(--fg)} .brief div{margin:6px 0;color:var(--dim)}
 button{background:#243044;color:var(--fg);border:1px solid var(--line);
   border-radius:6px;padding:8px 14px;margin-right:8px;cursor:pointer;font:inherit}
 button.go{background:#2b4a6f} button.red{background:#5c2230}
 button:disabled{opacity:.45;cursor:not-allowed}
 table{border-collapse:collapse;width:100%;font-size:12.5px}
 td,th{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left;
   vertical-align:top} th{color:var(--dim);font-weight:600}
 code{color:var(--acc);word-break:break-all}
 .ok{color:var(--ok)} .bad{color:var(--bad)} .dim{color:var(--dim)}
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
 @media(max-width:900px){.grid{grid-template-columns:1fr}}
 pre{margin:0;white-space:pre-wrap;word-break:break-all;font-size:12px}
</style></head><body>
<h1>Keebio BDN9 rev2 &mdash; QMK on ChibiOS, rehosted STM32F072 (Cortex-M0)</h1>
<div class="dim">HALucinator / unicorn &middot; no hardware, no vendor
 emulator &middot; the firmware is the vendor's own 46,880-byte image</div>

<details class="card brief" open><summary>What this page is</summary>
<div><b>Device.</b> A Keebio BDN9 rev2: a nine-key USB macropad with three
 rotary encoders, built on an STM32F072 (Cortex-M0) running QMK on ChibiOS.
 Everything below is produced by that firmware executing instruction by
 instruction inside an emulator &mdash; there is no hardware and no simulator of
 the device's behaviour.</div>
<div><b>Steps.</b> Press <i>Plug it in &amp; attack</i>. Wait
 (~1&ndash;3&nbsp;min: the firmware itself sleeps 1.5&nbsp;s before attaching to
 the bus, and everything after that is emulated at a fraction of real speed).
 Then press <i>Stalled-guest control</i> to see the same run with the CPU
 unable to execute.</div>
<div><b>What you're seeing.</b> <i>Verdict</i> is the pass/fail of every
 independent check. <i>Descriptors</i> compares each descriptor the firmware
 emitted against the bytes predicted from a static disassembly <i>before the
 firmware was ever booted</i> (see PROVENANCE.md, kept as its own commit).
 <i>Encoders</i> shows a knob being turned and the HID report that came back.
 <i>Stages</i> is the live log.</div>
<div><b>The attack.</b> The red button is a USB host that plugs itself in. It
 resets the bus, enumerates the macropad, reads every descriptor, changes HID
 class state in both directions, and turns the knobs &mdash; with <b>no
 pairing, no authentication and no user confirmation of any kind</b>. That is
 not a bug in this firmware; it is what USB HID is. It is shown here because
 the same reachability is what a malicious host, a hostile charger or a
 compromised hub gets from any keyboard you plug in.</div>
<div><b>Expect.</b> A landing run reports <code>milestone M4</code>,
 <code>landed true</code>, thirteen descriptors <span class="ok">MATCH</span>,
 a serial string equal to the die UID this run served, and six encoder reports
 matching a randomly ordered plan. A non-landing or patched device reports
 <code>landed false</code> and names the checks that failed. The control run
 must report <code>landed false</code> with every firmware-side field empty
 while the host stack stays perfectly alive &mdash; if it does not, the
 evidence above is not coming from the guest.</div>
</details>

<div class="card">
 <button class="go red" id="go">Plug it in &amp; attack</button>
 <button id="ctl">Stalled-guest control</button>
 <span id="stage" class="dim"></span>
</div>

<div class="grid">
 <div>
  <h2>Verdict</h2><div class="card" id="verdict" class="dim">not run yet</div>
  <h2>Identity</h2><div class="card"><pre id="ident" class="dim">-</pre></div>
  <h2>Encoders</h2><div class="card"><table id="enc"></table></div>
 </div>
 <div>
  <h2>Descriptors vs the pre-boot prediction</h2>
  <div class="card"><table id="desc"></table></div>
  <h2>Stages</h2><div class="card"><pre id="log" class="dim"></pre></div>
 </div>
</div>

<script>
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;',
 '>':'&gt;'}[c]));}
function render(s){
 document.getElementById('stage').textContent =
   s.busy ? ('running: ' + s.stage) : (s.stage==='done'?'finished':'idle');
 document.getElementById('go').disabled = s.busy;
 document.getElementById('ctl').disabled = s.busy;
 document.getElementById('log').textContent = s.log.map(e =>
   e.stage + (Object.keys(e.data).length ?
     '  ' + Object.entries(e.data).map(([k,v])=>k+'='+v).join('  ') : '')
 ).join('\\n');
 const r = s.result;
 if(!r){return;}
 let v = '<div><b>milestone</b> <code>'+esc(r.milestone)+'</code> &middot; '
   +'<b>landed</b> <span class="'+(r.landed?'ok':'bad')+'">'+r.landed
   +'</span> &middot; <b>usb_round_trip</b> <span class="'
   +(r.usb_round_trip?'ok':'bad')+'">'+r.usb_round_trip+'</span></div>'
   +'<table>';
 for(const [k,ok] of Object.entries(r.checks||{})){
   v += '<tr><td>'+esc(k)+'</td><td class="'+(ok?'ok':'bad')+'">'
      + (ok?'PASS':'FAIL')+'</td></tr>';}
 v += '</table>';
 document.getElementById('verdict').innerHTML = v;
 document.getElementById('ident').textContent =
   'VID:PID       ' + (r.vid_pid||'-') + '\\n' +
   'manufacturer  Keebio\\n' +
   'product       BDN9 Rev. 2\\n' +
   'die UID this run  ' + (r.die_uid_served_this_spawn||'-') + '\\n' +
   'serial the guest computed  ' + (r.serial_string||'-') + '\\n' +
   'HID keystroke round trip   ' + r.hid_keystroke_round_trip +
   '   (predicted false: the keymap is 9 x KC_TRANSPARENT)\\n' +
   'HID encoder  round trip    ' + r.hid_encoder_report_round_trip + '\\n' +
   'VIA / raw-HID interface    ' + r.raw_hid_via_interface_present +
   '   (absent from this build)';
 let d = '<tr><th>descriptor</th><th>vs prediction</th></tr>';
 for(const [k,ok] of Object.entries(r.descriptor_matches||{})){
   d += '<tr><td>'+esc(k)+'</td><td class="'+(ok?'ok':'bad')+'">'
      + (ok?'MATCH':'MISMATCH')+'</td></tr>';}
 document.getElementById('desc').innerHTML = d;
 let e = '<tr><th>plan</th><th>expected</th><th>observed</th></tr>';
 const pl=r.encoder_plan||[], ex=r.encoder_expected||[], ob=r.encoder_observed||[];
 for(let i=0;i<pl.length;i++){
   e += '<tr><td>'+esc(pl[i])+'</td><td><code>'+esc(ex[i])+'</code></td>'
      + '<td class="'+(ex[i]===ob[i]?'ok':'bad')+'"><code>'+esc(ob[i]||'-')
      + '</code></td></tr>';}
 document.getElementById('enc').innerHTML = e;
}
function poll(){fetch('/state').then(r=>r.json()).then(render).catch(()=>{});}
document.getElementById('go').onclick=()=>{fetch('/attack',{method:'POST'});
  setTimeout(poll,300);};
document.getElementById('ctl').onclick=()=>{fetch('/control',{method:'POST'});
  setTimeout(poll,300);};
setInterval(poll,1500); poll();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: D102, ANN001
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/state"):
            with _LOCK:
                self._send(200, json.dumps(_STATE))
        else:
            self._send(200, PAGE, "text/html; charset=utf-8")

    def do_POST(self):  # noqa: N802
        with _LOCK:
            busy = _STATE["busy"]
        if busy:
            self._send(409, json.dumps({"error": "busy"}))
            return
        if self.path.startswith("/attack"):
            threading.Thread(target=_run, args=(False,), daemon=True).start()
        elif self.path.startswith("/control"):
            threading.Thread(target=_run, args=(True,), daemon=True).start()
        else:
            self._send(404, json.dumps({"error": "no"}))
            return
        self._send(202, json.dumps({"started": True}))


def main() -> int:
    global ARGS
    ap = argparse.ArgumentParser(description="live panel for the rehosted BDN9")
    ap.add_argument("--port", type=int, default=spawn.PANEL_PORT)
    ap.add_argument("--bridge-port", type=int, default=spawn.BRIDGE_PORT)
    ap.add_argument("--no-open", action="store_true")
    ARGS = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler)
    url = "http://127.0.0.1:%d/" % ARGS.port
    print("panel: %s" % url, flush=True)
    if not ARGS.no_open:
        threading.Thread(target=lambda: (time.sleep(0.6),
                                         webbrowser.open(url)),
                         daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
