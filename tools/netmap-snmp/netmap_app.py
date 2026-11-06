# -*- coding: utf-8 -*-
"""
netmap：機房線路對應圖 Windows 程式
  - SNMP 掃描（圖形介面）
  - 監控服務：在內網提供網頁，定時讀取每個埠的流量與上下線狀態

執行：netmap.exe            開啟視窗
      netmap.exe --start    開啟視窗並啟動監控服務（開機自動啟動用，視窗會縮到工作列）
"""
import json, os, queue, sys, threading, time, webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

import netmap_snmp as ns
import netmap_server as srv

TITLE = "機房線路對應圖 netmap"
WEB = "https://coloplay1.github.io/netmap/"

FULLWIDTH = {ord("。"): ".", ord("．"): ".", ord("、"): " ", ord("，"): " ", ord("　"): " ", ord("／"): "/", ord("－"): "-", ord("："): ":", ord("～"): "~"}
def ascii_text(t):
    """全形數字與符號轉半形（中文輸入法開著時常打出全形）。"""
    out = []
    for ch in t.translate(FULLWIDTH):
        o = ord(ch)
        out.append(chr(o - 0xFEE0) if 0xFF01 <= o <= 0xFF5E else ch)
    return "".join(out)

def ascii_field(widget, var=None):
    """這個欄位只需要英數符號：關掉中文輸入法，並把全形字自動轉半形。"""
    if os.name == "nt":
        def off(_e=None):
            try:
                import ctypes
                ctypes.windll.imm32.ImmAssociateContextEx(widget.winfo_id(), None, 0)
            except Exception: pass
        widget.after_idle(off); widget.bind("<FocusIn>", off, add="+")
    if var is not None:
        busy = [False]
        def fix(*_):
            if busy[0]: return
            v = var.get(); n = ascii_text(v)
            if n != v:
                busy[0] = True
                try:
                    pos = widget.index("insert"); var.set(n); widget.icursor(pos)
                finally: busy[0] = False
        var.trace_add("write", fix)
    return widget

def resource(name):
    for d in ([sys._MEIPASS] if getattr(sys, "_MEIPASS", None) else []) + [os.path.dirname(os.path.abspath(__file__))]:
        p = os.path.join(d, name)
        if os.path.exists(p): return p
    return None

def ui_font():
    return ("Microsoft JhengHei UI", 10) if os.name == "nt" else ("Noto Sans CJK TC", 10)

class App:
    def __init__(s, root, autostart=False):
        s.root = root; s.q = queue.Queue()
        s.store = srv.Store(); s.service = srv.Service(s.store, log=lambda m: s.q.put(("svclog", m)))
        s.scan_thread = None; s.stop_scan = False; s.last_project = None
        root.title(TITLE); root.geometry("920x700"); root.minsize(800, 600)
        s.logo = None
        png = resource("netmap.png")
        if png:
            try:
                s.logo = tk.PhotoImage(file=png); root.iconphoto(True, s.logo)
                s.logo_small = s.logo.subsample(2, 2)
            except tk.TclError: s.logo = None
        ico = resource("netmap.ico")
        if os.name == "nt" and ico:
            try: root.iconbitmap(default=ico)
            except tk.TclError: pass
        st = ttk.Style()
        try: st.theme_use("vista" if os.name == "nt" else "clam")
        except tk.TclError: pass
        f = ui_font()
        root.option_add("*Font", f)
        for w in ("TLabel", "TButton", "TCheckbutton", "TRadiobutton", "TEntry", "TCombobox", "TNotebook.Tab", "Treeview", "TLabelframe.Label", "TSpinbox"):
            st.configure(w, font=f)
        st.configure("Title.TLabel", font=(f[0], 15, "bold")); st.configure("Muted.TLabel", foreground="#667085")
        st.configure("Accent.TButton", font=(f[0], 10, "bold")); st.configure("Treeview", rowheight=26)
        st.configure("On.TLabel", foreground="#1a7f37", font=(f[0], 11, "bold")); st.configure("Off.TLabel", foreground="#b42318", font=(f[0], 11, "bold"))

        head = ttk.Frame(root, padding=(16, 12, 16, 4)); head.pack(fill="x")
        if s.logo: ttk.Label(head, image=s.logo_small).pack(side="left", padx=(0, 10))
        ttk.Label(head, text="機房線路對應圖", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text=f"  SNMP 掃描與監控服務  v{srv.VERSION}", style="Muted.TLabel").pack(side="left", pady=(6, 0))
        ttk.Button(head, text="開啟網頁", command=s.open_web).pack(side="right")

        nb = ttk.Notebook(root); nb.pack(fill="both", expand=True, padx=12, pady=(4, 12)); s.nb = nb
        s.build_scan(ttk.Frame(nb, padding=12)); s.build_service(ttk.Frame(nb, padding=12)); s.build_about(ttk.Frame(nb, padding=16))
        root.protocol("WM_DELETE_WINDOW", s.on_close)
        root.after(120, s.pump); root.after(1500, s.refresh_service)
        if autostart or s.store.settings.get("autorun"):
            root.after(300, s.start_service)
        if autostart:
            root.after(800, root.iconify)

    # ───────────── 掃描分頁 ─────────────
    def build_scan(s, fr):
        s.nb.add(fr, text="  掃描  ")
        c = s.store.settings["snmp"]
        s.v_mode = tk.StringVar(value=s.store.settings.get("scan_mode", "snmp"))
        mode = ttk.Frame(fr); mode.pack(fill="x", pady=(0, 8))
        ttk.Radiobutton(mode, text="SNMP 掃描（防火牆、網管 Switch，可畫出連線與流量）", value="snmp", variable=s.v_mode, command=s.sync_mode).pack(side="left")
        ttk.Radiobutton(mode, text="網段探索（不需要 SNMP，列出在線的設備）", value="disc", variable=s.v_mode, command=s.sync_mode).pack(side="left", padx=(18, 0))
        top = ttk.LabelFrame(fr, text="掃描目標", padding=10); top.pack(fill="x")
        s.v_targets = tk.StringVar(value=s.store.settings.get("last_targets", ""))
        e = ttk.Entry(top, textvariable=s.v_targets); e.pack(fill="x"); e.focus_set(); ascii_field(e, s.v_targets)
        s.v_hint = tk.StringVar()
        ttk.Label(top, textvariable=s.v_hint, style="Muted.TLabel", wraplength=820).pack(anchor="w", pady=(6, 0))

        auth = ttk.LabelFrame(fr, text="SNMP 帳密（唯讀即可）", padding=10); auth.pack(fill="x", pady=(10, 0)); s.auth_box = auth
        s.v_ver = tk.StringVar(value={"1": "v1", "2c": "v2c", "3": "v3"}.get(c.get("version", "2c"), "v2c"))
        s.v_comm = tk.StringVar(value=srv.unprotect(c.get("community")) or "public")
        s.v_user = tk.StringVar(value=c.get("user", "")); s.v_aproto = tk.StringVar(value=c.get("auth_proto") or "SHA")
        s.v_akey = tk.StringVar(value=srv.unprotect(c.get("auth_key"))); s.v_pproto = tk.StringVar(value=c.get("priv_proto") or "AES")
        s.v_pkey = tk.StringVar(value=srv.unprotect(c.get("priv_key"))); s.v_ctx = tk.StringVar(value=c.get("context", ""))
        s.v_remember = tk.BooleanVar(value=True)
        g = ttk.Frame(auth); g.pack(fill="x")
        ttk.Label(g, text="版本").grid(row=0, column=0, sticky="w", padx=(0, 6))
        cb = ttk.Combobox(g, textvariable=s.v_ver, values=["v2c", "v3", "v1"], width=6, state="readonly"); cb.grid(row=0, column=1, sticky="w")
        cb.bind("<<ComboboxSelected>>", lambda e: s.sync_auth())
        s.lbl_comm = ttk.Label(g, text="Community"); s.lbl_comm.grid(row=0, column=2, sticky="w", padx=(18, 6))
        s.ent_comm = ttk.Entry(g, textvariable=s.v_comm, width=22, show="•"); s.ent_comm.grid(row=0, column=3, sticky="w"); ascii_field(s.ent_comm, s.v_comm)
        s.v3 = ttk.Frame(auth)
        for i, (lab, var, w, opts, show) in enumerate([("使用者", s.v_user, 16, None, ""), ("認證", s.v_aproto, 8, ["SHA", "SHA256", "SHA512", "MD5"], ""),
                                                        ("認證密碼", s.v_akey, 16, None, "•"), ("加密", s.v_pproto, 8, ["AES", "AES256", "DES"], ""),
                                                        ("加密密碼", s.v_pkey, 16, None, "•"), ("Context", s.v_ctx, 10, None, "")]):
            r, col = divmod(i, 3)
            ttk.Label(s.v3, text=lab).grid(row=r, column=col * 2, sticky="w", padx=(0 if col == 0 else 18, 6), pady=3)
            wdg = ttk.Combobox(s.v3, textvariable=var, values=opts, width=w, state="readonly") if opts else ascii_field(ttk.Entry(s.v3, textvariable=var, width=w, show=show), var)
            wdg.grid(row=r, column=col * 2 + 1, sticky="w", pady=3)
        ttk.Checkbutton(auth, text="記住帳密（以 Windows 帳號加密保存，監控服務也會用這組）", variable=s.v_remember).pack(anchor="w", pady=(8, 0))

        opt = ttk.Frame(fr); opt.pack(fill="x", pady=(8, 0)); s.opt_box = opt
        s.v_follow = tk.BooleanVar(value=True); s.v_fdb = tk.BooleanVar(value=True); s.v_nbr = tk.BooleanVar(value=True)
        s.v_timeout = tk.StringVar(value=str(c.get("timeout", 2)))
        ttk.Checkbutton(opt, text="沿著 LLDP／CDP 自動找鄰居", variable=s.v_follow).pack(side="left")
        ttk.Checkbutton(opt, text="從 MAC 表推斷終端設備", variable=s.v_fdb).pack(side="left", padx=(14, 0))
        ttk.Checkbutton(opt, text="建立沒掃到的鄰居（AP、電話）", variable=s.v_nbr).pack(side="left", padx=(14, 0))
        ttk.Label(opt, text="逾時（秒）").pack(side="left", padx=(14, 4))
        ttk.Spinbox(opt, from_=1, to=10, increment=1, textvariable=s.v_timeout, width=4).pack(side="left")

        s.disc_box = ttk.LabelFrame(fr, text="網段探索", padding=10)
        s.v_link = tk.BooleanVar(value=True)
        ttk.Label(s.disc_box, text="用 ping、常見連接埠與 ARP 表找出在線的設備，列出 IP、MAC、廠牌與名稱，並依開放的服務推測種類（印表機、攝影機、NAS、電腦）。看不出誰接在哪個埠，連線請在網頁上自己拉。",
                  style="Muted.TLabel", wraplength=820).pack(anchor="w")
        dr = ttk.Frame(s.disc_box); dr.pack(fill="x", pady=(8, 0))
        ttk.Button(dr, text="填入本機網段", command=lambda: s.v_targets.set(ns.local_subnet() or s.v_targets.get())).pack(side="left")
        ttk.Checkbutton(dr, text="先把設備都接到預設閘道（路由器），之後可自己改", variable=s.v_link).pack(side="left", padx=(14, 0))
        run = ttk.Frame(fr); run.pack(fill="x", pady=(10, 0)); s.run_box = run
        s.btn_scan = ttk.Button(run, text="開始掃描", style="Accent.TButton", command=s.start_scan); s.btn_scan.pack(side="left")
        s.btn_stop = ttk.Button(run, text="停止", command=s.cancel_scan, state="disabled"); s.btn_stop.pack(side="left", padx=(8, 0))
        s.pb = ttk.Progressbar(run, mode="determinate", length=260); s.pb.pack(side="left", padx=(16, 8))
        s.v_scanstat = tk.StringVar(value="輸入 IP 後按「開始掃描」"); ttk.Label(run, textvariable=s.v_scanstat, style="Muted.TLabel").pack(side="left")

        s.after_box = ttk.Frame(fr); s.after_box.pack(side="bottom", fill="x", pady=(10, 0))
        s.log = ScrolledText(fr, height=6, font=("Consolas", 10) if os.name == "nt" else ("DejaVu Sans Mono", 9), relief="flat", borderwidth=1)
        s.log.pack(fill="both", expand=True, pady=(10, 0)); s.log.configure(state="disabled")

        s.btn_use = ttk.Button(s.after_box, text="設為監控的圖（取代目前的圖）", command=s.use_scan, state="disabled"); s.btn_use.pack(side="left")
        s.btn_merge = ttk.Button(s.after_box, text="只把 SNMP 對應套到目前的圖", command=s.merge_scan, state="disabled"); s.btn_merge.pack(side="left", padx=(8, 0))
        s.btn_save = ttk.Button(s.after_box, text="另存 JSON…", command=s.save_scan, state="disabled"); s.btn_save.pack(side="left", padx=(8, 0))
        s.btn_try = ttk.Button(s.after_box, text="改用網段探索", command=s.try_discover)
        s.sync_auth(); s.sync_mode()

    def sync_mode(s):
        disc = s.v_mode.get() == "disc"
        if disc:
            s.auth_box.pack_forget(); s.opt_box.pack_forget(); s.disc_box.pack(fill="x", pady=(10, 0), before=s.run_box)
            s.v_hint.set("不填＝這台電腦所在的網段。也可以輸入網段或範圍：192.168.1.0/24  192.168.1.1-100")
            s.btn_scan.configure(text="開始探索") if hasattr(s, "btn_scan") else None
        else:
            s.disc_box.pack_forget(); s.auth_box.pack(fill="x", pady=(10, 0), before=s.run_box); s.opt_box.pack(fill="x", pady=(8, 0), before=s.run_box)
            s.v_hint.set("核心 Switch 的 IP 就夠了，程式會沿著 LLDP／CDP 找到其他設備。也可以輸入網段或範圍，用空白分隔：192.168.1.0/24  10.0.0.1-50")
            s.btn_scan.configure(text="開始掃描") if hasattr(s, "btn_scan") else None
        s.store.settings["scan_mode"] = s.v_mode.get()

    def try_discover(s):
        s.v_mode.set("disc"); s.sync_mode(); s.btn_try.pack_forget()
        t = s.v_targets.get().split()
        if len(t) == 1 and "/" not in t[0] and "-" not in t[0]:
            try: s.v_targets.set(str(ns.ipaddress.ip_network(t[0] + "/24", strict=False)))
            except ValueError: pass
        s.start_scan()

    def sync_auth(s):
        v3 = s.v_ver.get() == "v3"
        if v3:
            s.lbl_comm.grid_remove(); s.ent_comm.grid_remove(); s.v3.pack(fill="x", pady=(6, 0))
        else:
            s.v3.pack_forget(); s.lbl_comm.grid(); s.ent_comm.grid()

    def scan_opts(s):
        ver = {"v1": "1", "v2c": "2c", "v3": "3"}[s.v_ver.get()]
        try: to = float(s.v_timeout.get())
        except ValueError: to = 2.0
        return ns.opts(version=ver, community=s.v_comm.get().strip() or "public", user=s.v_user.get().strip() or None, auth_proto=s.v_aproto.get(),
                       auth_key=s.v_akey.get() or None, priv_proto=s.v_pproto.get(), priv_key=s.v_pkey.get() or None, context=s.v_ctx.get().strip(),
                       timeout=to, no_follow=not s.v_follow.get(), no_fdb=not s.v_fdb.get(), no_neighbors=not s.v_nbr.get())

    def remember(s):
        c = s.store.settings["snmp"]; s.store.settings["last_targets"] = s.v_targets.get().strip()
        if s.v_remember.get():
            c.update(version={"v1": "1", "v2c": "2c", "v3": "3"}[s.v_ver.get()], community=srv.protect(s.v_comm.get().strip() or "public"),
                     user=s.v_user.get().strip(), auth_proto=s.v_aproto.get(), auth_key=srv.protect(s.v_akey.get()), priv_proto=s.v_pproto.get(),
                     priv_key=srv.protect(s.v_pkey.get()), context=s.v_ctx.get().strip())
            try: c["timeout"] = float(s.v_timeout.get())
            except ValueError: pass
        s.store.save_settings()

    def write(s, text):
        s.log.configure(state="normal"); s.log.insert("end", text + "\n"); s.log.see("end"); s.log.configure(state="disabled")

    def start_scan(s):
        targets = ascii_text(s.v_targets.get()).replace(",", " ").replace(";", " ").split()
        disc = s.v_mode.get() == "disc"
        if disc and not targets:
            sub = ns.local_subnet()
            if sub: s.v_targets.set(sub); targets = [sub]
        if not targets: messagebox.showinfo(TITLE, "請先輸入要掃描的 IP 或網段。"); return
        if disc:
            s.store.settings["last_targets"] = " ".join(targets); s.store.save_settings(); s.stop_scan = False
            s.btn_scan.configure(state="disabled"); s.btn_stop.configure(state="normal"); s.btn_try.pack_forget()
            for b in (s.btn_use, s.btn_merge, s.btn_save): b.configure(state="disabled")
            s.log.configure(state="normal"); s.log.delete("1.0", "end"); s.log.configure(state="disabled"); s.pb["value"] = 0
            link = s.v_link.get()
            def dwork():
                t0 = time.time()
                try:
                    proj = ns.discover(targets, log=lambda m: s.q.put(("log", m)), progress=lambda d, t, ph: s.q.put(("prog", (d, t, ph))),
                                       stop=lambda: s.stop_scan, link_gateway=link)
                    s.q.put(("done", (proj if proj and proj["devices"] else None, [], time.time() - t0)))
                except Exception as e:
                    s.q.put(("error", str(e)))
            s.scan_thread = threading.Thread(target=dwork, daemon=True); s.scan_thread.start(); return
        if s.v_ver.get() == "v3" and not s.v_user.get().strip(): messagebox.showinfo(TITLE, "SNMPv3 需要填使用者。"); return
        s.remember(); a = s.scan_opts(); s.stop_scan = False; s.btn_try.pack_forget()
        s.btn_scan.configure(state="disabled"); s.btn_stop.configure(state="normal")
        for b in (s.btn_use, s.btn_merge, s.btn_save): b.configure(state="disabled")
        s.log.configure(state="normal"); s.log.delete("1.0", "end"); s.log.configure(state="disabled"); s.pb["value"] = 0
        def work():
            t0 = time.time()
            try:
                proj, devs, failed = ns.run_scan(a, targets, log=lambda m: s.q.put(("log", m)), progress=lambda d, t, ph: s.q.put(("prog", (d, t, ph))),
                                                 stop=lambda: s.stop_scan)
                s.q.put(("done", (proj, failed, time.time() - t0)))
            except Exception as e:
                s.q.put(("error", str(e)))
        s.scan_thread = threading.Thread(target=work, daemon=True); s.scan_thread.start()

    def cancel_scan(s):
        s.stop_scan = True; s.v_scanstat.set("停止中…")

    def use_scan(s):
        if not s.last_project: return
        if s.store.project.get("devices") and not messagebox.askyesno(TITLE, "要用這次的掃描結果取代監控服務目前的圖嗎？\n\n你在網頁上手動加的配線架、資訊座、備註都會被取代（舊的圖會自動備份）。\n\n只想讓監控對應到設備、保留目前的圖，請改按「只把 SNMP 對應套到目前的圖」。"):
            return
        bk = os.path.join(s.store.dir, "backup"); os.makedirs(bk, exist_ok=True)
        json.dump(s.store.project, open(os.path.join(bk, f"before-scan-{time.strftime('%Y%m%d-%H%M%S')}.json"), "w", encoding="utf-8"), ensure_ascii=False)
        s.store.set_project(s.last_project); s.service.poller.poke()
        messagebox.showinfo(TITLE, f"已設為監控的圖：{len(s.last_project['devices'])} 台設備、{len(s.last_project['cables'])} 條線。\n\n啟動監控服務後打開網頁就能看到。")
        s.refresh_service()

    def merge_scan(s):
        if not s.last_project: return
        if not s.store.project.get("devices"):
            messagebox.showinfo(TITLE, "監控服務目前沒有圖，請改按「設為監控的圖」。"); return
        proj = json.loads(json.dumps(s.store.project)); nd, npt = srv.merge_snmp(proj, s.last_project)
        s.store.set_project(proj); s.service.poller.poke()
        messagebox.showinfo(TITLE, f"已把 SNMP 對應套到目前的圖：對到 {nd} 台設備、{npt} 個埠。\n\n對不到的設備請確認網頁上設備的 IP 或名稱和掃描結果一致。")

    def save_scan(s):
        if not s.last_project: return
        p = filedialog.asksaveasfilename(title="另存掃描結果", defaultextension=".json", initialfile=f"netmap-scan-{time.strftime('%Y%m%d-%H%M')}.json",
                                         filetypes=[("netmap 專案檔", "*.json")])
        if p:
            json.dump(s.last_project, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            s.write(f"已存成 {p}，可到 {WEB} 匯入。")

    # ───────────── 監控服務分頁 ─────────────
    def build_service(s, fr):
        s.nb.add(fr, text="  監控服務  ")
        top = ttk.Frame(fr); top.pack(fill="x")
        s.v_state = tk.StringVar(value="○ 已停止"); s.lbl_state = ttk.Label(top, textvariable=s.v_state, style="Off.TLabel"); s.lbl_state.pack(side="left")
        s.btn_svc = ttk.Button(top, text="啟動服務", style="Accent.TButton", command=s.toggle_service); s.btn_svc.pack(side="right")
        ttk.Button(top, text="立即輪詢", command=lambda: s.service.poller.poke()).pack(side="right", padx=(0, 8))
        urlf = ttk.Frame(fr); urlf.pack(fill="x", pady=(8, 0))
        ttk.Label(urlf, text="網頁網址：").pack(side="left")
        s.url_box = ttk.Frame(urlf); s.url_box.pack(side="left")
        ttk.Label(fr, text="同一個內網的電腦用瀏覽器打開上面的網址，就能看到同一張圖和每個埠的即時狀態。第一次啟動時 Windows 防火牆會詢問，請按「允許存取」。",
                  style="Muted.TLabel", wraplength=840).pack(anchor="w", pady=(4, 0))

        cfg = ttk.LabelFrame(fr, text="設定", padding=10); cfg.pack(fill="x", pady=(10, 0))
        st = s.store.settings
        s.v_port = tk.StringVar(value=str(st.get("port", 8080))); s.v_int = tk.StringVar(value=str(st.get("interval", 60)))
        s.v_keep = tk.StringVar(value=str(st.get("retention_days", 7))); s.v_lan = tk.BooleanVar(value=bool(st.get("lan_edit")))
        s.v_boot = tk.BooleanVar(value=bool(st.get("autostart"))); s.v_auto = tk.BooleanVar(value=bool(st.get("autorun", True)))
        r1 = ttk.Frame(cfg); r1.pack(fill="x")
        ttk.Label(r1, text="網頁埠").pack(side="left"); ascii_field(ttk.Entry(r1, textvariable=s.v_port, width=7), s.v_port).pack(side="left", padx=(6, 18))
        ttk.Label(r1, text="輪詢間隔（秒）").pack(side="left")
        ttk.Combobox(r1, textvariable=s.v_int, values=["30", "60", "120", "300"], width=6).pack(side="left", padx=(6, 18))
        ttk.Label(r1, text="流量紀錄保留（天）").pack(side="left"); ttk.Spinbox(r1, from_=1, to=90, textvariable=s.v_keep, width=5).pack(side="left", padx=(6, 0))
        r2 = ttk.Frame(cfg); r2.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(r2, text="允許內網其他電腦編輯圖（不勾＝其他電腦只能看）", variable=s.v_lan, command=s.save_service_cfg).pack(side="left")
        r3 = ttk.Frame(cfg); r3.pack(fill="x", pady=(4, 0))
        ttk.Checkbutton(r3, text="開啟程式時自動啟動服務", variable=s.v_auto, command=s.save_service_cfg).pack(side="left")
        cbb = ttk.Checkbutton(r3, text="Windows 開機時自動執行", variable=s.v_boot, command=s.toggle_boot); cbb.pack(side="left", padx=(18, 0))
        if os.name != "nt": cbb.state(["disabled"])
        ttk.Button(r1, text="套用", command=s.apply_service_cfg).pack(side="right")

        s.svclog = ScrolledText(fr, height=4, font=("Consolas", 9) if os.name == "nt" else ("DejaVu Sans Mono", 8), relief="flat")
        s.svclog.pack(side="bottom", fill="x", pady=(6, 0)); s.svclog.configure(state="disabled")
        s.v_svcfoot = tk.StringVar(value="尚未輪詢"); ttk.Label(fr, textvariable=s.v_svcfoot, style="Muted.TLabel", wraplength=840).pack(side="bottom", anchor="w", pady=(6, 0))
        cols = ("name", "host", "state", "ports", "traffic")
        s.tree = ttk.Treeview(fr, columns=cols, show="headings", height=8)
        for k, t, w in (("name", "設備", 200), ("host", "SNMP 位址", 150), ("state", "狀態", 110), ("ports", "埠（上線／離線）", 140), ("traffic", "最忙的埠", 240)):
            s.tree.heading(k, text=t); s.tree.column(k, width=w, anchor="w")
        s.tree.pack(fill="both", expand=True, pady=(10, 0))
        s.tree.tag_configure("down", foreground="#b42318"); s.tree.tag_configure("up", foreground="#1a7f37")

    def save_service_cfg(s):
        st = s.store.settings; st["lan_edit"] = s.v_lan.get(); st["autorun"] = s.v_auto.get(); s.store.save_settings()

    def apply_service_cfg(s):
        st = s.store.settings
        try:
            port = int(s.v_port.get()); itv = max(10, int(float(s.v_int.get()))); keep = max(1, int(s.v_keep.get()))
        except ValueError:
            messagebox.showwarning(TITLE, "網頁埠、輪詢間隔、保留天數請填數字。"); return
        restart = s.service.running and port != st.get("port")
        st.update(port=port, interval=itv, retention_days=keep); s.save_service_cfg()
        if restart:
            s.service.stop(); s.service = srv.Service(s.store, log=lambda m: s.q.put(("svclog", m))); s.start_service()
        else:
            s.service.poller.poke()
        s.refresh_service()

    def toggle_boot(s):
        on = s.v_boot.get(); s.store.settings["autostart"] = on; s.store.save_settings()
        if os.name != "nt": return
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            if on:
                exe = sys.executable if getattr(sys, "frozen", False) else f'"{sys.executable.replace("python.exe", "pythonw.exe")}" "{os.path.abspath(__file__)}"'
                cmd = f'"{exe}" --start' if getattr(sys, "frozen", False) else f"{exe} --start"
                winreg.SetValueEx(k, "netmap", 0, winreg.REG_SZ, cmd)
            else:
                try: winreg.DeleteValue(k, "netmap")
                except FileNotFoundError: pass
            winreg.CloseKey(k)
        except Exception as e:
            messagebox.showwarning(TITLE, f"無法設定開機自動執行：{e}")

    def start_service(s):
        if s.service.running: return
        try:
            s.service.start()
        except OSError as e:
            messagebox.showerror(TITLE, f"服務無法啟動：網頁埠 {s.store.settings.get('port')} 可能已被其他程式使用。\n\n請換一個埠（例如 8081）後按「套用」再啟動。\n\n（{e}）")
        s.refresh_service()

    def toggle_service(s):
        if s.service.running:
            s.service.stop(); s.service = srv.Service(s.store, log=lambda m: s.q.put(("svclog", m)))
        else:
            s.start_service()
        s.refresh_service()

    def refresh_service(s):
        try:
            on = s.service.running
            s.v_state.set("● 執行中" if on else "○ 已停止"); s.lbl_state.configure(style="On.TLabel" if on else "Off.TLabel")
            s.btn_svc.configure(text="停止服務" if on else "啟動服務")
            for w in s.url_box.winfo_children(): w.destroy()
            if on:
                for u in s.service.urls():
                    l = ttk.Label(s.url_box, text=u, foreground="#1d6fd8", cursor="hand2"); l.pack(side="left", padx=(0, 12))
                    l.bind("<Button-1>", lambda e, u=u: webbrowser.open(u))
                ttk.Button(s.url_box, text="複製", command=lambda: (s.root.clipboard_clear(), s.root.clipboard_append(s.service.urls()[0]))).pack(side="left")
            else:
                ttk.Label(s.url_box, text="（服務未啟動）", style="Muted.TLabel").pack(side="left")
            stat = s.service.poller.status; devs = {d["id"]: d for d in s.store.project.get("devices", [])}
            s.tree.delete(*s.tree.get_children())
            tg = s.service.poller.targets()
            for d, host in tg:
                ds = stat.get("devices", {}).get(d["id"])
                ps = [stat["ports"][p["id"]] for p in d.get("ports", []) if p["id"] in stat.get("ports", {})]
                upn = sum(1 for p in ps if p.get("up")); dn = sum(1 for p in ps if p.get("up") is False)
                busy = max(ps, key=lambda p: p.get("util") or 0, default=None)
                bt = ""
                if busy and busy.get("util") is not None:
                    bt = f"{busy['util']:.0%}　↓{fmt_bps(busy.get('in'))} ↑{fmt_bps(busy.get('out'))}"
                state = "等待輪詢" if not ds else ("正常" if ds["up"] else ds.get("err") or "沒有回應")
                s.tree.insert("", "end", values=(d.get("name", ""), host, state, f"{upn} ／ {dn}" if ps else "—", bt), tags=(("up" if ds and ds["up"] else "down") if ds else (),))
            if not tg:
                s.tree.insert("", "end", values=("（還沒有要監控的設備）", "先到「SNMP 掃描」掃描並設為監控的圖", "", "", ""))
            pl = s.service.poller
            if pl.last_cycle:
                s.v_svcfoot.set(f"最後輪詢 {time.strftime('%H:%M:%S', time.localtime(pl.last_cycle))}，耗時 {pl.cycle_secs} 秒；每 {s.store.settings.get('interval')} 秒更新。資料位置：{s.store.dir}")
        finally:
            s.root.after(4000, s.refresh_service)

    # ───────────── 關於 ─────────────
    def build_about(s, fr):
        s.nb.add(fr, text="  說明  ")
        txt = ("這支程式有兩個功能：\n\n"
               "1. SNMP 掃描：讀取防火牆、Switch、AP 的 SNMP 資料（LLDP／CDP、介面、VLAN、PoE、LACP、MAC 表），自動產生網路圖。\n"
               "2. 監控服務：在這台電腦上提供網頁版的線路圖，並定時讀取每個埠的流量、使用率與上下線狀態，保留歷史紀錄。\n\n"
               "只會讀取（SNMP GET），不會修改任何設備設定。帳密以目前的 Windows 帳號加密保存。\n\n"
               "使用步驟：\n"
               "  ① 在「SNMP 掃描」輸入核心 Switch 的 IP 與 community，按「開始掃描」。\n"
               "  ② 掃描完成後按「設為監控的圖」，或「只把 SNMP 對應套到目前的圖」。\n"
               "  ③ 到「監控服務」按「啟動服務」，用瀏覽器打開顯示的網址。\n\n"
               "配線架、資訊座等被動元件不會回應 SNMP，請在網頁上手動補上；它們不影響流量顯示。")
        ttk.Label(fr, text=txt, wraplength=820, justify="left").pack(anchor="w")
        b = ttk.Frame(fr); b.pack(anchor="w", pady=(16, 0))
        ttk.Button(b, text="開啟資料資料夾", command=lambda: open_path(s.store.dir)).pack(side="left")
        ttk.Button(b, text="線上版網頁", command=lambda: webbrowser.open(WEB)).pack(side="left", padx=(8, 0))

    # ───────────── misc ─────────────
    def open_web(s):
        if s.service.running: webbrowser.open(s.service.urls()[0])
        else: webbrowser.open(WEB)

    def pump(s):
        try:
            while True:
                k, v = s.q.get_nowait()
                if k == "log": s.write(v)
                elif k == "svclog":
                    s.svclog.configure(state="normal"); s.svclog.insert("end", time.strftime("%H:%M:%S ") + v + "\n"); s.svclog.see("end"); s.svclog.configure(state="disabled")
                elif k == "prog":
                    d, t, ph = v; s.pb["maximum"] = max(1, t); s.pb["value"] = d
                    s.v_scanstat.set({"probe": f"探測位址 {d}/{t}", "collect": f"讀取第 {d + 1} 台設備…", "detail": f"讀取名稱與服務 {d}/{t}", "done": "整理結果…"}.get(ph, ""))
                elif k in ("done", "error"):
                    s.btn_scan.configure(state="normal"); s.btn_stop.configure(state="disabled")
                    if k == "error": s.write(f"錯誤：{v}"); s.v_scanstat.set("掃描失敗"); continue
                    proj, failed, secs = v; s.last_project = proj
                    if not proj:
                        s.v_scanstat.set("沒有掃到設備")
                        if s.v_mode.get() == "snmp":
                            s.write("\n沒有收集到任何設備。家用路由器、電腦、手機通常不支援 SNMP；只想列出網路上有哪些設備，可以按下面的「改用網段探索」。")
                            s.btn_try.pack(side="right")
                        else:
                            s.write("\n沒有找到在線的設備。請確認網段正確，以及這台電腦有連上這個網路。")
                    else:
                        s.v_scanstat.set(f"完成：{len(proj['devices'])} 台設備、{len(proj['cables'])} 條線（{secs:.1f} 秒）")
                        s.write(f"\n完成：{len(proj['devices'])} 台設備、{len(proj['cables'])} 條線。")
                        s.write("下一步：按下面的「設為監控的圖」，再到「監控服務」啟動服務；或「另存 JSON」到網頁匯入。")
                        for b in (s.btn_use, s.btn_merge, s.btn_save): b.configure(state="normal")
        except queue.Empty:
            pass
        s.root.after(120, s.pump)

    def on_close(s):
        if s.service.running:
            r = messagebox.askyesnocancel(TITLE, "監控服務執行中。\n\n「是」：縮到工作列，服務繼續執行\n「否」：停止服務並結束程式")
            if r is None: return
            if r: s.root.iconify(); return
            s.service.stop()
        s.root.destroy()

def fmt_bps(v):
    if v is None: return "—"
    for u, d in (("G", 1e9), ("M", 1e6), ("K", 1e3)):
        if v >= d: return f"{v / d:.1f}{u}"
    return f"{v:.0f}"

def open_path(p):
    try:
        if os.name == "nt": os.startfile(p)
        else: webbrowser.open("file://" + p)
    except Exception: pass

def main():
    if "--service" in sys.argv:
        return srv.main()
    try:
        if os.name == "nt":
            import ctypes; ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception: pass
    root = tk.Tk()
    App(root, autostart="--start" in sys.argv)
    root.mainloop()

if __name__ == "__main__":
    main()
