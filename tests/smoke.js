// RackTrace 冒煙測試：電腦、手機、監控服務三種情境。CI 每次推上去都會跑，任何一項失敗就不發布。
// 用法：node tests/smoke.js [服務網址，預設 http://127.0.0.1:18799/]
const {chromium,devices}=require('playwright');const path=require('path');
const FILE='file://'+path.resolve(__dirname,'..','index.html');const SRV=process.argv[2]||'http://127.0.0.1:18799/';
let fails=0;const ok=(c,m)=>{console.log((c?'  ✓ ':'  ✗ ')+m);if(!c)fails++};
async function page(b,opt){const ctx=await b.newContext(opt);const p=await ctx.newPage();p.errs=[];p.on('pageerror',e=>p.errs.push(e.message));p.on('dialog',d=>d.accept());return p}
(async()=>{const b=await chromium.launch();
  console.log('電腦（線上版）');
  let p=await page(b,{viewport:{width:1440,height:900}});await p.goto(FILE);await p.waitForTimeout(1500);
  await p.click('[data-tpl="office"]');await p.waitForTimeout(1200);
  ok(await p.evaluate(()=>S.devices.length>10&&S.cables.length>10),'範例載入');
  ok(await p.evaluate(()=>{const d=S.devices.find(x=>x.type==='end'&&x.ports.length);ui.sel={dev:d.id};renderAll();return document.querySelectorAll('#wires g.hot').length>0}),'點設備亮出路徑');
  ok(await p.evaluate(()=>{const c=S.cables[0];ui.sel={cable:c.id};prefs.ctxOn=true;renderAll();return !$('ctx').hidden}),'點線出現屬性列');
  for(const [n,fn] of [['資料檢查','openDataCheck()'],['待接線清單','openPendList()'],['現場快速卡','openQuickCard()'],['線標列印','openLabels()'],['分享','openShare(null)']]){
    await p.evaluate(f=>{closeModal();return eval(f)},fn);await p.waitForTimeout(300);ok(await p.evaluate(()=>!!document.querySelector('#mod')),n+'視窗');}
  await p.evaluate(()=>{closeModal();setView('triage')});await p.waitForTimeout(300);ok(await p.evaluate(()=>!!document.querySelector('#triageView .tri-col')),'排障視圖');
  for(const v of ['rack','table','map']){await p.evaluate(v=>setView(v),v);await p.waitForTimeout(200)}
  await p.evaluate(()=>{S.plans=[{id:'pl1',name:'3F',w:1200,h:800,shapes:[{id:'s1',k:'rect',x:40,y:40,w:200,h:120,t:'會議室'}]}];S.devices.filter(d=>d.type==='seat').forEach((d,i)=>d.plan={id:'pl1',x:300+i*150,y:300});setView('plan')});await p.waitForTimeout(300);
  ok(await p.evaluate(()=>document.querySelectorAll('#planView .plcard').length>0&&document.querySelector('#planView .plcard .pj i')),'平面圖顯示座位與線號');
  ok(await p.evaluate(()=>JSON.stringify(projData()).includes('"plans"')),'平面圖會存進專案');
  ok(await p.evaluate(()=>{S.racks=S.racks.length?S.racks:[{name:'R1',size:42}];const rn=S.racks[0].name;let d=S.devices.find(x=>x.rack===rn);if(!d){d=S.devices.find(x=>rackable(x));d.rack=rn}planRackModal(rn);const a=!!document.querySelector('#inspBody [data-rkact]')&&!document.querySelector('#planView .plbox:not(.plmin) .rkrow');document.querySelector(`#inspBody [data-rkd="${d.id}"] [data-rkedit]`).click();const b=ui.sel.dev===d.id&&!!document.querySelector('#inspBody [data-rkback]');document.querySelector('#inspBody [data-rkback]').click();const c=ui.sel.rack===rn&&!!document.querySelector('#inspBody [data-rkd]');ui.sel=null;ui.detail=null;renderAll();return a&&b&&c}),'機櫃顯示在右側屬性欄，可進入設備再返回');
  ok(await p.evaluate(()=>{ui.plRack=null;const seat=S.devices.find(d=>d.plan&&d.type==='seat'&&d.ports.some(p=>I.cab[p.id]));if(!seat)return true;const t=planTargets(seat,null);const sw=[...S.devices].find(d=>!TYPES[d.type].pass&&d.type!=='end'&&d.ports.some(p=>planTargets(d,p.id).devs.has(seat.id)));if(!sw)return true;ui.sel={dev:sw.id};ui.detail=sw.id;renderAll();const ok1=!!document.querySelector('#inspBody .plports [data-plhp]');const pp=sw.ports.find(p=>planTargets(sw,p.id).devs.has(seat.id));document.querySelector(`#inspBody [data-plhp="${pp.id}"]`).click();return ok1&&document.querySelector(`#planView [data-pdev="${seat.id}"]`).classList.contains('plhi')}),'點設備的埠會標出平面圖上的座位');
  ok(await p.evaluate(()=>{const seat=S.devices.find(d=>d.plan&&d.type==='seat'&&planSwLinks(d).length);if(!seat)return true;ui.plSel=null;document.querySelector(`#planView [data-pdev="${seat.id}"]`).click();const pop=$('plPop');const ok1=!!pop&&!!pop.querySelector('.ppg button.on');document.querySelector(`#planView [data-pdev="${seat.id}"]`).dispatchEvent(new MouseEvent('contextmenu',{bubbles:true,cancelable:true,clientX:200,clientY:200}));const ok2=!!$('plMenu');$('plMenu')&&$('plMenu').remove();return ok1&&ok2}),'點座位跳出交換器埠位、右鍵選單');
  await p.evaluate(()=>setView('map'));
  ok(await p.evaluate(()=>{const n=S.cables.length;snap();S.cables.pop();renderAll();undo();return S.cables.length===n}),'復原');
  ok(!p.errs.length,'沒有 JavaScript 錯誤'+(p.errs.length?'：'+p.errs.slice(0,3).join(' | '):''));
  console.log('手機');
  p=await page(b,{...devices['iPhone 13']});await p.goto(FILE);await p.waitForTimeout(1500);await p.click('[data-tpl="office"]');await p.waitForTimeout(1200);
  const tabs=await p.evaluate(()=>{const bs=[...document.querySelectorAll('.views button')].map(e=>e.getBoundingClientRect());return bs.every((r,i)=>i===0||r.left>=bs[i-1].right-1)&&bs.every(r=>r.right<=innerWidth)});ok(tabs,'頁籤不重疊');
  await p.click('#topFold');await p.waitForTimeout(300);ok(await p.evaluate(()=>document.querySelector('header.top').classList.contains('folded')),'收合工具列');
  ok(await p.evaluate(()=>{const c=S.cables[0];ui.sel={cable:c.id};prefs.ctxOn=true;renderAll();const t=document.querySelector('header.top').getBoundingClientRect().bottom,r=$('ctx').getBoundingClientRect();return !$('ctx').hidden&&r.top>=t-1&&r.height>40}),'屬性列在工具列下方');
  ok(!p.errs.length,'沒有 JavaScript 錯誤'+(p.errs.length?'：'+p.errs.slice(0,3).join(' | '):''));
  console.log('監控服務');
  p=await page(b,{viewport:{width:1440,height:900}});
  try{await p.goto(SRV);await p.waitForTimeout(3000);
    ok(await p.evaluate(()=>!!SRV&&S.devices.length>0),'從服務載入圖');
    const r0=await p.evaluate(()=>ui.srvRev);await p.evaluate(()=>{snap();S.devices[0].note='ci-'+Date.now();save()});await p.waitForTimeout(2500);
    ok(await p.evaluate(r0=>ui.srvRev>r0,r0),'修改會存回服務');
    ok(await p.evaluate(async()=>{const j=await api('/api/projects');return Array.isArray(j.list)}),'專案清單 API');
    ok(!p.errs.length,'沒有 JavaScript 錯誤'+(p.errs.length?'：'+p.errs.slice(0,3).join(' | '):''));
  }catch(e){ok(false,'連不到服務：'+e.message)}
  await b.close();console.log(fails?`\n${fails} 項失敗`:'\n全部通過');process.exit(fails?1:0)})();
