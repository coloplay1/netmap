# -*- coding: utf-8 -*-
"""
netmap：機房線路對應圖 Windows 程式
  - SNMP 掃描（圖形介面）
  - 監控服務：在內網提供網頁，定時讀取每個埠的流量與上下線狀態

執行：netmap.exe            開啟視窗
      netmap.exe --start    開啟視窗並啟動監控服務（開機自動啟動用，視窗會縮到工作列）
"""
import json, os, queue, re, sys, threading, time, webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

import netmap_snmp as ns
import netmap_server as srv
import netmap_collect as col
import netmap_sshmon as sm

VERSION_URL = os.environ.get("NETMAP_VERSION_URL") or "https://coloplay1.github.io/netmap/version.json"
DOWNLOAD_URL = "https://github.com/coloplay1/netmap/releases/latest/download/netmap.exe"


def newer(a, b):
    """True when version string a is newer than b (1.10.0 > 1.9.2)."""
    def parts(v): return [int(x) for x in re.findall(r"\d+", v)[:4]] or [0]
    try: return parts(a) > parts(b)
    except Exception: return False

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
        s.upd = ttk.Label(head, text="", foreground="#ffffff", background="#2563EB", cursor="hand2", padding=(8, 2))
        s.upd.bind("<Button-1>", lambda e: s.open_update())

        nb = ttk.Notebook(root); nb.pack(fill="both", expand=True, padx=12, pady=(4, 12)); s.nb = nb
        s.collector = None
        s.build_scan(ttk.Frame(nb, padding=12)); s.build_service(ttk.Frame(nb, padding=12)); s.build_collect(ttk.Frame(nb, padding=12)); s.build_about(ttk.Frame(nb, padding=16))
        root.protocol("WM_DELETE_WINDOW", s.on_close)
        root.after(120, s.pump); root.after(1500, s.refresh_service)
        s.update_info = None
        threading.Thread(target=s.check_update, daemon=True).start()
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

        s.btn_use = ttk.Button(s.after_box, text="在網頁開啟結果", style="Accent.TButton", command=s.use_scan, state="disabled"); s.btn_use.pack(side="left")
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

    def choose(s, title, msg, options, default=0):
        """自訂對話框：按鈕直接寫出要做的事。回傳選到的索引，關掉視窗回傳 None。"""
        dlg = tk.Toplevel(s.root); dlg.title(title); dlg.transient(s.root); dlg.resizable(False, False)
        res = [None]
        fr = ttk.Frame(dlg, padding=18); fr.pack(fill="both", expand=True)
        ttk.Label(fr, text=msg, wraplength=440, justify="left").pack(anchor="w")
        row = ttk.Frame(fr); row.pack(fill="x", pady=(16, 0))
        for i, t in enumerate(options):
            b = ttk.Button(row, text=t, style="Accent.TButton" if i == default else "TButton", command=lambda i=i: (res.__setitem__(0, i), dlg.destroy()))
            b.pack(side="left", padx=(0 if i == 0 else 8, 0))
            if i == default: b.focus_set()
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.update_idletasks()
        x = s.root.winfo_rootx() + (s.root.winfo_width() - dlg.winfo_width()) // 2; y = s.root.winfo_rooty() + (s.root.winfo_height() - dlg.winfo_height()) // 3
        dlg.geometry(f"+{max(0, x)}+{max(0, y)}"); dlg.grab_set(); s.root.wait_window(dlg)
        return res[0]

    def local_url(s):
        return f"http://127.0.0.1:{int(s.store.settings.get('port', 8080))}/"

    def show_in_web(s, project, how="replace"):
        """把結果放進監控服務、確定服務在跑，然後用瀏覽器打開。"""
        if how == "replace":
            if s.store.project.get("devices"):
                bk = os.path.join(s.store.dir, "backup"); os.makedirs(bk, exist_ok=True)
                json.dump(s.store.project, open(os.path.join(bk, f"before-scan-{time.strftime('%Y%m%d-%H%M%S')}.json"), "w", encoding="utf-8"), ensure_ascii=False)
            s.store.set_project(project); msg = f"已帶入網頁：{len(project['devices'])} 台設備、{len(project['cables'])} 條線"
        else:
            proj = json.loads(json.dumps(s.store.project)); nd, npt = srv.merge_snmp(proj, project)
            s.store.set_project(proj); msg = f"已更新目前的圖：對到 {nd} 台設備、{npt} 個埠"
        s.service.poller.poke()
        if not s.service.running: s.start_service()
        s.refresh_service()
        if s.service.running:
            webbrowser.open(s.local_url()); s.v_scanstat.set(msg + "，已在瀏覽器開啟"); s.write(f"\n{msg}。網頁：{s.local_url()}（其他電腦用 {s.service.urls()[0]}）")

    def use_scan(s, auto=False):
        if not s.last_project: return
        if s.store.project.get("devices"):
            n = len(s.store.project["devices"])
            i = s.choose("在網頁開啟結果", f"網頁上已經有一張圖（{n} 台設備）。這次的結果要怎麼處理？\n\n‧ 取代：換成這次的結果（舊的圖會自動備份）\n‧ 保留：保留你手動畫的配線架、備註，只把 SNMP 對應套上去，讓監控對到設備",
                         ["取代成這次的結果", "保留目前的圖，只更新對應", "先不要"])
            if i is None or i == 2:
                if not auto: return
                s.v_scanstat.set("掃描完成，按「在網頁開啟結果」可帶入網頁"); return
            s.show_in_web(s.last_project, "replace" if i == 0 else "merge")
        else:
            s.show_in_web(s.last_project, "replace")

    def merge_scan(s):
        if not s.last_project: return
        if not s.store.project.get("devices"):
            s.show_in_web(s.last_project, "replace"); return
        s.show_in_web(s.last_project, "merge")

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
        ttk.Button(top, text="加入 SSH 設備…", command=s.add_ssh_dialog).pack(side="right", padx=(0, 8))
        ttk.Button(top, text="移除 SSH 監控", command=s.remove_ssh).pack(side="right", padx=(0, 8))
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
        ttk.Label(r1, text="詳細紀錄保留（天）").pack(side="left"); ttk.Spinbox(r1, from_=1, to=90, textvariable=s.v_keep, width=5).pack(side="left", padx=(6, 0))
        ttk.Label(r1, text="（MRTG 流量圖另外保存約 2 年）", style="Muted.TLabel").pack(side="left", padx=(6, 0))
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
        for k, t, w in (("name", "設備", 200), ("host", "監控方式／位址", 170), ("state", "狀態", 110), ("ports", "埠（上線／離線）", 140), ("traffic", "最忙的埠", 240)):
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

    # ───────────── SSH 監控設備 ─────────────
    def add_ssh_dialog(s):
        dlg = tk.Toplevel(s.root); dlg.title("加入 SSH 監控設備"); dlg.transient(s.root); dlg.resizable(False, False)
        fr = ttk.Frame(dlg, padding=18); fr.pack(fill="both", expand=True)
        ttk.Label(fr, text="給沒有 SNMP 的設備用：家用路由器（ASUS 等）、Linux 主機、NAS、OpenWrt。"
                           "程式會用 SSH 登入，定時讀取每個介面的流量（只讀取，不改設定），畫出即時流量與 MRTG 流量圖。",
                  wraplength=460, justify="left", style="Muted.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
        v_ip, v_port, v_user, v_pw = tk.StringVar(), tk.StringVar(value="22"), tk.StringVar(), tk.StringVar()
        for r, (lab, var, w, show) in enumerate((("設備 IP", v_ip, 22, ""), ("SSH 埠", v_port, 8, ""), ("帳號", v_user, 22, ""), ("密碼", v_pw, 22, "•")), start=1):
            ttk.Label(fr, text=lab).grid(row=r, column=0, sticky="w", pady=4, padx=(0, 10))
            e = ascii_field(ttk.Entry(fr, textvariable=var, width=w, show=show), var); e.grid(row=r, column=1, sticky="w")
            if r == 1: e.focus_set()
        v_msg = tk.StringVar(value="帳密以 Windows 帳號加密保存在這台電腦，不會出現在網頁上。")
        ttk.Label(fr, textvariable=v_msg, wraplength=460, justify="left", style="Muted.TLabel").grid(row=5, column=0, columnspan=4, sticky="w", pady=(10, 0))
        row = ttk.Frame(fr); row.grid(row=6, column=0, columnspan=4, sticky="e", pady=(14, 0))
        btn = ttk.Button(row, text="連線並加入", style="Accent.TButton"); btn.pack(side="right")
        ttk.Button(row, text="取消", command=dlg.destroy).pack(side="right", padx=(0, 8))

        def done(info, err, user, pw):
            if not dlg.winfo_exists(): return
            btn.configure(state="normal")
            if err: v_msg.set(f"沒有加入：{err}"); return
            if not info["ports"]: v_msg.set("連上了，但找不到有流量的介面。"); return
            d, created = s.store.add_ssh_device(info, user, pw)
            dlg.destroy()
            if not s.service.running: s.start_service()
            s.service.poller.poke(); s.refresh_service()
            names = "、".join(lab for _i, lab, _n in info["ports"])
            what = " ".join(x for x in (info.get("brand"), info.get("model")) if x) or info.get("name")
            i = s.choose("已加入 SSH 監控", f"{'已加入' if created else '已更新'}「{d['name']}」（{what}）。\n\n監控的介面：{names}\n\n"
                         "約 1 分鐘後就有即時流量，10 分鐘後流量圖開始出現。", ["開啟流量圖", "開啟網頁", "關閉"])
            if i == 0: webbrowser.open(s.local_url() + "#mrtg=all")
            elif i == 1: webbrowser.open(s.local_url())

        def go(_e=None):
            ip, user, pw = v_ip.get().strip(), v_user.get().strip(), v_pw.get()
            try: port = int(v_port.get() or 22)
            except ValueError: v_msg.set("SSH 埠要填數字（通常是 22）"); return
            if not ip or not user or not pw: v_msg.set("請填設備 IP、帳號與密碼。"); return
            btn.configure(state="disabled"); v_msg.set(f"連線 {ip}:{port}…")
            def work():
                try: info, err = sm.probe(ip, port, user, pw), None
                except sm.SshError as e: info, err = None, str(e)
                except Exception as e: info, err = None, f"{e.__class__.__name__}: {e}"
                s.root.after(0, lambda: done(info, err, user, pw))
            threading.Thread(target=work, daemon=True).start()
        btn.configure(command=go); dlg.bind("<Return>", go); dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.update_idletasks()
        dlg.geometry(f"+{s.root.winfo_rootx() + 80}+{s.root.winfo_rooty() + 90}"); dlg.grab_set()

    def remove_ssh(s):
        devs = {d["id"]: d for d in s.store.project.get("devices", []) if d.get("sshmon")}
        sel = [i for i in s.tree.selection() if i in devs]
        if not devs: messagebox.showinfo(TITLE, "目前沒有用 SSH 監控的設備。"); return
        if not sel: messagebox.showinfo(TITLE, "請先在下方的列表點選要移除的 SSH 設備。"); return
        d = devs[sel[0]]
        if s.choose("移除 SSH 監控", f"停止用 SSH 監控「{d['name']}」（{d['sshmon']['host']}），並刪除保存的帳密？\n\n設備會留在圖上，已記錄的流量圖也會保留。"
                    "\n\n不再需要的話，記得到設備上關閉 SSH。", ["移除", "取消"], default=1) != 0: return
        s.store.remove_ssh(d["id"])
        L = s.service.poller.links.pop(d["sshmon"]["host"], None)
        if L: L.close()
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
                ttk.Button(s.url_box, text="流量圖（MRTG）", command=lambda: webbrowser.open(s.local_url() + "#mrtg=all")).pack(side="left", padx=(8, 0))
            else:
                ttk.Label(s.url_box, text="（服務未啟動）", style="Muted.TLabel").pack(side="left")
            stat = s.service.poller.status; devs = {d["id"]: d for d in s.store.project.get("devices", [])}
            keep = s.tree.selection()
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
                shown = ("SSH " + host[6:]) if host.startswith("ssh://") else ("SNMP " + host)
                s.tree.insert("", "end", iid=d["id"], values=(d.get("name", ""), shown, state, f"{upn} ／ {dn}" if ps else "—", bt), tags=(("up" if ds and ds["up"] else "down") if ds else (),))
            sel = [i for i in keep if s.tree.exists(i)]
            if sel: s.tree.selection_set(sel)
            if not tg:
                s.tree.insert("", "end", values=("（還沒有要監控的設備）", "用「SNMP 掃描」掃描並設為監控的圖；沒有 SNMP 的設備按「加入 SSH 設備…」", "", "", ""))
            pl = s.service.poller
            if pl.last_cycle:
                s.v_svcfoot.set(f"最後輪詢 {time.strftime('%H:%M:%S', time.localtime(pl.last_cycle))}，耗時 {pl.cycle_secs} 秒；每 {s.store.settings.get('interval')} 秒更新。資料位置：{s.store.dir}")
        finally:
            s.root.after(4000, s.refresh_service)

    # ───────────── 收集樣本 ─────────────
    def build_collect(s, fr):
        s.nb.add(fr, text="  收集樣本  ")
        s.sample_dir = os.path.join(s.store.dir, "samples")
        ttk.Label(fr, text="給「log 分析告警」與「設定檔自動備份」開發用：收集你們設備實際的 log 與登入畫面，存成檔案後傳給開發者。只接收與讀取，不會修改設備設定。",
                  style="Muted.TLabel", wraplength=860).pack(anchor="w")
        lf = ttk.LabelFrame(fr, text="① 收集 log 樣本（Syslog／SNMP Trap）", padding=10); lf.pack(fill="x", pady=(8, 0))
        s.v_ips = tk.StringVar(value="、".join(srv.local_ips()))
        tip = ttk.Frame(lf); tip.pack(fill="x")
        ttk.Label(tip, text="把設備的 Syslog 伺服器（或 SNMP Trap 目的地）設成這台電腦：").pack(side="left")
        ttk.Label(tip, textvariable=s.v_ips, foreground="#1d6fd8").pack(side="left")
        row = ttk.Frame(lf); row.pack(fill="x", pady=(6, 0))
        s.v_sys = tk.BooleanVar(value=True); s.v_trp = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Syslog（UDP 514）", variable=s.v_sys).pack(side="left")
        ttk.Checkbutton(row, text="SNMP Trap（UDP 162）", variable=s.v_trp).pack(side="left", padx=(12, 0))
        s.btn_col = ttk.Button(row, text="開始收集", style="Accent.TButton", command=s.toggle_collect); s.btn_col.pack(side="left", padx=(18, 0))
        ttk.Button(row, text="傳送測試訊息", command=s.test_collect).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="開啟樣本資料夾", command=lambda: (os.makedirs(s.sample_dir, exist_ok=True), open_path(s.sample_dir))).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="在家怎麼測試？", command=s.home_help).pack(side="left", padx=(8, 0))
        s.v_colstat = tk.StringVar(value="尚未開始"); ttk.Label(lf, textvariable=s.v_colstat, style="Muted.TLabel").pack(anchor="w", pady=(6, 0))
        s.colog = ScrolledText(lf, height=5, font=("Consolas", 9) if os.name == "nt" else ("DejaVu Sans Mono", 8), relief="flat")
        s.colog.pack(fill="x", pady=(6, 0)); s.colog.configure(state="disabled")

        sf = ttk.LabelFrame(fr, text="② 設備登入紀錄（SSH，給設定檔備份用）", padding=10); sf.pack(fill="both", expand=True, pady=(8, 0))
        g = ttk.Frame(sf); g.pack(fill="x")
        s.v_sh = tk.StringVar(); s.v_sport = tk.StringVar(value="22"); s.v_su = tk.StringVar(); s.v_sp = tk.StringVar(); s.v_se = tk.StringVar()
        names = [p["name"] for p in col.PROFILES.values()]; s.prof_keys = list(col.PROFILES)
        s.v_prof = tk.StringVar(value=names[0]); s.v_cmds = tk.StringVar()
        cells = [("設備 IP", s.v_sh, 16, ""), ("埠", s.v_sport, 5, ""), ("帳號", s.v_su, 14, ""), ("密碼", s.v_sp, 14, "•"), ("enable 密碼（選填）", s.v_se, 12, "•")]
        for i, (lab, var, w, show) in enumerate(cells):
            ttk.Label(g, text=lab).grid(row=0, column=i * 2, sticky="w", padx=(0 if i == 0 else 12, 4))
            ascii_field(ttk.Entry(g, textvariable=var, width=w, show=show), var).grid(row=0, column=i * 2 + 1, sticky="w")
        g2 = ttk.Frame(sf); g2.pack(fill="x", pady=(6, 0))
        ttk.Label(g2, text="設備類型").pack(side="left")
        cb = ttk.Combobox(g2, textvariable=s.v_prof, values=names, width=28, state="readonly"); cb.pack(side="left", padx=(4, 12))
        cb.bind("<<ComboboxSelected>>", lambda e: s.v_cmds.set("；".join(col.PROFILES[s.prof_keys[names.index(s.v_prof.get())]]["cmds"])))
        ttk.Label(g2, text="要執行的指令（；分隔，空白＝依類型預設）").pack(side="left")
        ttk.Entry(g2, textvariable=s.v_cmds, width=34).pack(side="left", padx=(4, 0), fill="x", expand=True)
        g3 = ttk.Frame(sf); g3.pack(fill="x", pady=(6, 0))
        s.btn_ssh = ttk.Button(g3, text="登入並記錄", style="Accent.TButton", command=s.start_ssh); s.btn_ssh.pack(side="left")
        s.v_sshstat = tk.StringVar(value="密碼不會存檔；紀錄裡的密碼、community、金鑰會自動換成 ***，傳出前仍請自己看過一遍。")
        ttk.Label(g3, textvariable=s.v_sshstat, style="Muted.TLabel", wraplength=680).pack(side="left", padx=(12, 0))
        s.sshlog = ScrolledText(sf, height=5, font=("Consolas", 9) if os.name == "nt" else ("DejaVu Sans Mono", 8), relief="flat")
        s.sshlog.pack(fill="both", expand=True, pady=(6, 0)); s.sshlog.configure(state="disabled")


    def home_help(s):
        messagebox.showinfo("在家怎麼測試", "用家裡的路由器（以華碩為例，實際選單名稱依機種與韌體可能不同）：\n\n"
            "① log 樣本\n  1. 這裡按「開始收集」，第一次 Windows 防火牆詢問時按「允許存取」。\n"
            "  2. 登入路由器管理頁（例如 http://192.168.50.1），在「系統記錄」或「系統管理 ▸ 系統設定」找「遠端記錄伺服器（Remote Log Server）」，填這台電腦的 IP 後套用。\n"
            "  3. 拔插一次接在路由器上的網路線，或在管理頁故意打錯一次密碼登入，這裡就會出現 log。\n\n"
            "② 登入紀錄\n  1. 在「系統管理 ▸ 系統設定」啟用 SSH（只開區域網路），帳密同路由器管理員。\n"
            "  2. 這裡填路由器 IP、帳密，設備類型選「Linux / 華碩等家用路由器」，按「登入並記錄」。\n\n"
            "測完記得把路由器的 SSH 關掉。家用設備的 log 格式和公司設備不同，這次主要是確認工具能用；分析規則還是要用公司設備的樣本。")

    def colwrite(s, box, text):
        box.configure(state="normal"); box.insert("end", text + "\n"); box.see("end")
        if int(box.index("end-1c").split(".")[0]) > 600: box.delete("1.0", "100.0")
        box.configure(state="disabled")

    def toggle_collect(s):
        if s.collector:
            paths = s.collector.stop(); s.collector = None; s.btn_col.configure(text="開始收集")
            s.v_colstat.set("已停止，樣本存在：" + "、".join(os.path.basename(p) for p in paths)); return
        if not (s.v_sys.get() or s.v_trp.get()): return
        s.collector = col.LogCollector(s.sample_dir, on_event=lambda k, src, t: s.q.put(("colev", (k, src, t))))
        errs = s.collector.start(syslog=s.v_sys.get(), trap=s.v_trp.get())
        for e in errs: s.colwrite(s.colog, "⚠ " + e)
        if not s.collector.socks:
            s.collector = None; s.v_colstat.set("無法開始"); return
        s.btn_col.configure(text="停止並存檔"); s.v_colstat.set("收集中…（第一次會跳出 Windows 防火牆詢問，請按「允許存取」）")
        s.colwrite(s.colog, f"開始收集：{'、'.join(('Syslog UDP 514' if k == 'syslog' else 'Trap UDP 162') for k in s.collector.socks)}。到設備上把 log 目的地設成 {s.v_ips.get()}，拔插一次網路線或故意打錯一次登入密碼，就會產生事件。")

    def test_collect(s):
        if not s.collector:
            s.colwrite(s.colog, "請先按「開始收集」。"); return
        try:
            if "syslog" in s.collector.socks: col.send_test_syslog("127.0.0.1", s.collector.ports["syslog"])
            if "trap" in s.collector.socks: col.send_test_trap("127.0.0.1", s.collector.ports["trap"])
        except OSError as e: s.colwrite(s.colog, f"測試訊息送不出去：{e}")

    def start_ssh(s):
        host = s.v_sh.get().strip(); user = s.v_su.get().strip()
        if not host or not user: s.v_sshstat.set("請填設備 IP 與帳號。"); return
        try: port = int(s.v_sport.get() or 22)
        except ValueError: port = 22
        names = [p["name"] for p in col.PROFILES.values()]; prof = s.prof_keys[names.index(s.v_prof.get())]
        cmds = [c.strip() for c in re.split(r"[；;\n]", s.v_cmds.get()) if c.strip()] or None
        pw, en = s.v_sp.get(), s.v_se.get()
        s.btn_ssh.configure(state="disabled"); s.sshlog.configure(state="normal"); s.sshlog.delete("1.0", "end"); s.sshlog.configure(state="disabled")
        def work():
            try:
                txt, used = col.ssh_capture(host, user, pw, profile=prof, port=port, enable_pw=en, commands=cmds, log=lambda m: s.q.put(("sshlog", m)))
                os.makedirs(s.sample_dir, exist_ok=True)
                path = os.path.join(s.sample_dir, f"login-{host.replace(':', '_')}-{time.strftime('%Y%m%d-%H%M%S')}.txt")
                open(path, "w", encoding="utf-8").write(txt)
                s.q.put(("sshdone", (path, txt, col.PROFILES[used]["name"])))
            except Exception as e:
                msg = str(e) or type(e).__name__
                if "Authentication" in type(e).__name__: msg = "帳號或密碼錯誤"
                elif isinstance(e, (TimeoutError, OSError)) and "timed out" in msg: msg = "連線逾時：請確認 IP、埠號，以及設備有開 SSH"
                elif "Connection refused" in msg or "10061" in msg: msg = "連線被拒絕：設備沒有開 SSH，或埠號不對"
                s.q.put(("sshdone", (None, msg, "")))
        threading.Thread(target=work, daemon=True).start()

    # ───────────── 關於 ─────────────
    def build_about(s, fr):
        s.nb.add(fr, text="  說明  ")
        txt = ("這支程式有兩個功能：\n\n"
               "1. SNMP 掃描：讀取防火牆、Switch、AP 的 SNMP 資料（LLDP／CDP、介面、VLAN、PoE、LACP、MAC 表），自動產生網路圖。\n"
               "2. 監控服務：在這台電腦上提供網頁版的線路圖，並定時讀取每個埠的流量、使用率與上下線狀態，保留歷史紀錄；每個埠都有 MRTG 式的日／週／月／年流量圖。\n\n"
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
                elif k == "colev":
                    kind, src, t = v; c = s.collector.counts if s.collector else {}
                    s.colwrite(s.colog, f"{time.strftime('%H:%M:%S')} {'SYSLOG' if kind == 'syslog' else 'TRAP  '} {src:<15} {t}")
                    s.v_colstat.set(f"收集中：Syslog {c.get('syslog', 0)} 筆、Trap {c.get('trap', 0)} 筆，來自 {len(s.collector.sources) if s.collector else 0} 台設備")
                elif k == "sshlog": s.colwrite(s.sshlog, v)
                elif k == "sshdone":
                    path, txt, pname = v; s.btn_ssh.configure(state="normal")
                    if path:
                        s.v_sshstat.set(f"完成（{pname}），已存成 {os.path.basename(path)}，按「開啟樣本資料夾」可找到。")
                        s.colwrite(s.sshlog, "\n".join(txt.splitlines()[:400]))
                    else:
                        s.v_sshstat.set(f"失敗：{txt}"); s.colwrite(s.sshlog, f"失敗：{txt}")
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
                        for b in (s.btn_use, s.btn_merge, s.btn_save): b.configure(state="normal")
                        s.root.after(150, lambda: s.use_scan(auto=True))
        except queue.Empty:
            pass
        s.root.after(120, s.pump)

    # ---------- update check ----------
    def check_update(s):
        """Read version.json from the website; never blocks or bothers the user when offline."""
        if os.environ.get("NETMAP_NO_UPDATE_CHECK"): return
        try:
            import urllib.request
            req = urllib.request.Request(VERSION_URL, headers={"User-Agent": f"netmap/{srv.VERSION}"})
            info = json.loads(urllib.request.urlopen(req, timeout=6).read().decode("utf-8"))
            if newer(str(info.get("exe", "")), srv.VERSION):
                s.update_info = info
                s.root.after(0, s.show_update)
        except Exception:
            pass

    def show_update(s):
        i = s.update_info or {}
        s.upd.configure(text=f"有新版本 v{i.get('exe')}，點此下載")
        s.upd.pack(side="right", padx=(0, 10))

    def open_update(s):
        i = s.update_info or {}
        msg = f"有新版本 netmap.exe v{i.get('exe')}（目前 v{srv.VERSION}）。\n\n{i.get('title', '')}\n\n下載後把新的 netmap.exe 取代舊檔即可，設定與流量紀錄會保留。\n要現在下載嗎？"
        if messagebox.askyesno(TITLE, msg):
            webbrowser.open(i.get("download") or DOWNLOAD_URL)
        if i.get("notes") and messagebox.askyesno(TITLE, "要順便看更新內容嗎？"):
            webbrowser.open(i["notes"])

    def on_close(s):
        if s.service.running:
            i = s.choose("關閉程式", "監控服務正在執行，其他電腦可能正在看網頁。\n\n結束程式後網頁就打不開，也不會再記錄流量。",
                         ["結束程式", "縮到工作列，繼續監控", "取消"], default=0)
            if i is None or i == 2: return
            if i == 1: s.root.iconify(); return
        s.quit_app()

    def quit_app(s):
        """確實結束：停止掃描與服務，不等背景執行緒（SNMP 逾時中的輪詢）跑完。"""
        s.stop_scan = True
        if s.collector:
            try: s.collector.stop()
            except Exception: pass
        try: s.store.save_settings()
        except Exception: pass
        t = threading.Thread(target=s.service.stop, daemon=True); t.start(); t.join(3)
        try: s.root.destroy()
        except Exception: pass
        os._exit(0)

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
