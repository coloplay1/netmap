// 由 manual.html 產生 RackTrace-manual.pdf：封面（直式標誌）、目錄（含頁碼，兩階段排版）、內文。
const {chromium}=require('playwright');const fs=require('fs');const {execFileSync}=require('child_process');
const ROOT='/home/claude/netmap',OUT=ROOT+'/RackTrace-manual.pdf',TMP='/tmp/claude-0/t9/pdf-pass1.pdf';
const ver=JSON.parse(fs.readFileSync(ROOT+'/version.json','utf8'));
const logo=fs.readFileSync(ROOT+'/racktrace-logo.svg','utf8').replace(/width="\d+" height="\d+"/,'width="100%" height="100%"').replace(/<rect width="800" height="900" fill="#FFFFFF"\/>/,'');
const CSS=`@page{size:A4;margin:15mm 15mm 17mm}
*{box-shadow:none!important;text-shadow:none!important;filter:none!important;backdrop-filter:none!important}
html{scroll-padding-top:0}body{background:#fff!important;font-size:10.4pt;line-height:1.7}
header.top,nav.toc,#tocBtn,.hero,.toTop,#toTop,.foot{display:none!important}
.wrap{display:block!important;max-width:none!important;padding:0!important}main{max-width:none!important;padding:0!important;margin:0!important}
section{break-before:page;padding-top:0!important;margin-top:0!important;border:0!important}
h2{margin-top:0!important;font-size:19pt!important}h2,h3,h4{break-after:avoid}
figure,table,pre,.tip,.note,.tw,.steps li,details,.grid2{break-inside:avoid}
figure img{max-height:118mm;width:auto!important;max-width:100%!important;margin:0 auto;display:block}
figure.mid img{max-height:95mm}figure.narrow img{max-height:100mm}
a{color:inherit!important;text-decoration:none!important}
details>summary{list-style:none}details>summary::-webkit-details-marker{display:none}
@page :first{margin:0}
#cover{height:296mm;break-after:page;text-align:left}
#cover .chero{margin:0;height:150mm;background:#14283f;color:#fff;display:flex;align-items:center;gap:12mm;padding:0 18mm;position:relative}
#cover .chero:after{content:"";position:absolute;left:0;right:0;bottom:0;height:3mm;background:linear-gradient(90deg,#f5b82e 0 34%,#2a8fe8 34% 67%,#7a8699 67%)}
#cover .card{flex:none;width:62mm;height:50mm;background:#fff;border-radius:6mm;padding:5mm;display:flex;align-items:center;justify-content:center}
#cover .card .lg{width:100%;height:100%}
#cover .ht .n{font-size:34pt;font-weight:600;letter-spacing:.01em;line-height:1.1}
#cover .ht .s{font-size:10pt;letter-spacing:.22em;color:#9fb3c8;margin-top:3mm}
#cover .ht .z{font-size:15pt;margin-top:3mm;letter-spacing:.12em}
#cover .ht .u{font-size:21pt;margin-top:12mm;letter-spacing:.4em;font-weight:500}
#cover .info{padding:14mm 18mm 0;font-size:10.5pt;color:#333;line-height:1.95}
#cover .info b{color:#111}
#cover .v{margin-top:8mm;font-size:10pt;color:#555;line-height:1.9}
#tocp{break-after:page}#tocp h2{font-size:19pt;margin:0 0 6mm}
#tocp ol{list-style:none;padding:0;margin:0}#tocp li{display:flex;gap:6px;align-items:baseline;padding:1.6mm 0;font-size:11pt}
#tocp li.sub{padding:.6mm 0 .6mm 8mm;font-size:9.6pt;color:#475569}
#tocp li .dots{flex:1;border-bottom:1px dotted #aaa;transform:translateY(-1mm)}#tocp li .pg{min-width:8mm;text-align:right}`;
async function render(pages){const b=await chromium.launch();const p=await b.newPage();await p.route(/fonts\.g/,r=>r.abort());
  await p.goto('file://'+ROOT+'/manual.html',{waitUntil:'load'});
  const F='file:///tmp/claude-0/fonts/node_modules/@fontsource/';
  for(const u of ['noto-sans-tc/400.css','noto-sans-tc/500.css','noto-sans-tc/700.css','inter/400.css','inter/500.css','inter/700.css','jetbrains-mono/400.css'])await p.addStyleTag({url:F+u});
  await p.addStyleTag({content:'body,button,input{font-family:"Inter","Noto Sans TC",sans-serif!important}code,pre,kbd{font-family:"JetBrains Mono","Noto Sans TC",monospace!important}'});
  const heads=await p.evaluate(({css,logo,ver,pages})=>{document.documentElement.setAttribute('data-theme','light');
    const st=document.createElement('style');st.textContent=css;document.head.appendChild(st);
    document.querySelectorAll('img').forEach(i=>i.loading='eager');document.querySelectorAll('details').forEach(d=>d.open=true);
    const heads=[];document.querySelectorAll('main section').forEach(s=>{const h=s.querySelector('h2');if(!h||s.id==='changelog'&&false)return;const nn=h.querySelector('.n');const nt=nn?nn.textContent:'';heads.push({id:s.id,t:h.textContent.replace(nt,'').trim(),n:nt,lv:1});s.querySelectorAll('h3[id]').forEach(h3=>heads.push({id:h3.id,t:h3.textContent.trim(),lv:2}))});
    const d=new Date();const cover=document.createElement('div');cover.id='cover';
    cover.innerHTML=`<div class="chero"><div class="card"><div class="lg">${logo.replace(/viewBox="[^"]*"/,'viewBox="110 100 560 360"')}</div></div><div class="ht"><div class="n">RackTrace</div><div class="s">DATA CENTER NETWORK CABLE MAPPING</div><div class="z">機房線路對應圖</div><div class="u">使 用 手 冊</div></div></div><div class="info"><b>點一個埠，整條線路亮起來。</b><br>手動畫圖、查線、故障查線；搭配本地端 netmap.exe 可自動掃描、即時監控與流量排行。<div class="v">網頁版 v${ver.web}　·　netmap.exe v${ver.exe}<br>${d.getFullYear()} 年 ${d.getMonth()+1} 月<br>https://coloplay1.github.io/netmap/</div></div>`;
    const toc=document.createElement('div');toc.id='tocp';toc.innerHTML='<h2>目錄</h2><ol>'+heads.map(h=>`<li class="${h.lv===2?'sub':''}"><span>${h.n?h.n+'　':''}${h.t.replace(/</g,'&lt;')}</span><span class="dots"></span><span class="pg">${pages&&pages[h.id]?pages[h.id]:''}</span></li>`).join('')+'</ol>';
    const main=document.querySelector('main');main.prepend(toc);main.prepend(cover);return heads},{css:CSS,logo,ver,pages});
  await p.waitForFunction(()=>[...document.images].every(i=>i.complete),null,{timeout:30000}).catch(()=>{});await p.evaluate(async()=>{document.body.offsetHeight;await document.fonts.ready});await p.waitForTimeout(600);
  const file=pages?OUT:TMP;
  await p.pdf({path:file,format:'A4',printBackground:true,preferCSSPageSize:true,outline:true,displayHeaderFooter:true,
    headerTemplate:'<div></div>',footerTemplate:`<div style="width:100%;font-size:8px;color:#888;padding:0 15mm;display:flex;justify-content:space-between;font-family:sans-serif"><span>RackTrace 使用手冊 · v${ver.web}</span><span class="pageNumber"></span></div>`});
  await b.close();return heads}
(async()=>{const heads=await render(null);
  // 第一次排版後找出每個標題在第幾頁
  const pages=JSON.parse(execFileSync('python3',['/tmp/claude-0/t/pdf_pages.py',TMP,JSON.stringify(heads)]).toString());
  await render(pages);console.log('pages found',Object.keys(pages).length,'/',heads.length);
  console.log(execFileSync('python3',['-c',`import pypdf;r=pypdf.PdfReader('${OUT}');print(len(r.pages),'pages')`]).toString())})();
