'use strict';
// Extends the shared console with observable node health and layered authorization.
const choose=(key,title,options,value)=>`<label>${esc(title)}<select name="${key}">${options.map(([v,t])=>`<option value="${esc(v)}" ${String(v)===String(value)?'selected':''}>${esc(t)}</option>`).join('')}</select></label>`;
const nodeNames=ids=>ids.map(id=>data.nodes.find(n=>n.id===id)?.name||id).join('、')||'无';
const gb=v=>(v/1024**3).toFixed(2)+' GB';
const previousNodeCard=nodeCard;
nodeCard=function(n){const display={...n,host:n.host==='local'?(n.health?.addresses?.join(', ')||'本机'):n.host};return previousNodeCard(display).replace('<div class="actions">',meta('已下发 / 应授权用户',n.assigned_user_count+' / '+n.desired_user_count)+meta('有历史流量的用户',n.historical_used_user_count)+`<div class="actions">${btn('查看详情','node-details',n.id)}`);};
const previousUserCard=userCard;
userCard=function(u){return previousUserCard(u).replace('<div class="actions">',meta('规则允许的节点',nodeNames(u.entitled_node_ids))+meta('应下发节点',nodeNames(u.desired_node_ids))+`<div class="actions">${btn('编辑 / 节点权限','user-edit',u.id)}`);};

planForm=function(id){
 const p=data.plans.find(x=>x.id===id)||{};
 const nodes=data.nodes.map(n=>`<label class="node-check"><input type="checkbox" name="node_${n.id}" ${p.node_ids?.includes(n.id)?'checked':''}><span>${esc(n.name)} <small>${esc(n.domain)} · ${esc(state(n.state))}</small></span></label>`).join('');
 form(id?'编辑套餐与节点规则':'新增套餐与节点规则',
  field('name','套餐名称','text',p.name)+choose('access_mode','节点匹配方式',[['selected','指定节点（只允许勾选项）'],['tags','标签匹配（任意标签命中）']],p.access_mode||'selected')+
  `<section class="full node-options" id="selected-nodes"><h3>套餐关联节点</h3>${nodes||'<p>请先新增节点。</p>'}</section>`+
  `<section class="full" id="tag-options">${field('tags','匹配标签，逗号分隔','text',p.tags?JSON.parse(p.tags).join(','):'',false)}<p>新增节点只要命中标签，会自动获得本套餐授权。</p></section>`+
  field('quota_gb','总流量 GB','number',p.quota?p.quota/1024**3:100)+field('days','有效天数','number',p.days||30)+field('price','价格说明','text',p.price||'0'),
  x=>submit(id?'plan.edit':'plan.add',{...x,id,node_ids:data.nodes.filter(n=>x['node_'+n.id]==='on').map(n=>n.id)}),
  '指定节点模式只授权勾选项；标签模式自动匹配。修改后会同步现有用户，但不会重置现有用户的流量账期、额度或有效期。用户单独设置的允许/禁用仍优先。');
 const selectMode=modal.querySelector('[name="access_mode"]');
 const update=()=>{modal.querySelector('#selected-nodes').hidden=selectMode.value!=='selected';modal.querySelector('#tag-options').hidden=selectMode.value!=='tags';};selectMode.onchange=update;update();
};

function editUser(id){
 const u=data.users.find(x=>x.id===id);const plan=data.plans.find(x=>x.id===u.plan_id);
 const expiry=u.expires?new Date(u.expires*1000-new Date(u.expires*1000).getTimezoneOffset()*60000).toISOString().slice(0,16):'';
 const rules=data.nodes.map(n=>choose('rule_'+n.id,n.name,[['inherit','继承套餐'],['allow','单独允许'],['deny','单独禁用']],u.node_rules[n.id]||'inherit')).join('');
 form('编辑用户与节点权限',field('name','用户名','text',u.name)+choose('plan_id','所属套餐 / 等级',data.plans.map(p=>[p.id,p.name]),u.plan_id)+
  (u.is_admin?'<div class="notice full">管理员订阅：不限流量、永久有效；节点授权仍受套餐和用户规则约束。</div>':field('quota_gb','本期流量上限 GB','number',u.quota/1024**3)+field('expires','结束时间（当前设备时区）','datetime-local',expiry))+
  `<div class="notice full" id="plan-preview">套餐节点：${esc(nodeNames(plan?.matched_node_ids||[]))}</div><section class="full"><h3>每个节点的用户规则</h3><p>单独允许可超出套餐范围；单独禁用会阻止套餐授权。切回继承后按套餐决定。</p><div class="form-grid">${rules||'<p>暂无节点</p>'}</div></section>`,
  p=>{const node_rules={};for(const n of data.nodes){const v=p['rule_'+n.id];if(v==='allow'||v==='deny')node_rules[n.id]=v;}return submit('user.edit',{id,name:p.name,plan_id:p.plan_id,quota_gb:p.quota_gb,expires:u.is_admin?0:Math.floor(new Date(p.expires).getTime()/1000),node_rules});},
  '修改会触发服务端授权同步和订阅刷新，不更换现有订阅链接。停用、到期、超额的用户不会因单独允许而重新获得权限。离线节点撤权可能待处理，请查看任务与节点状态。');
 const picker=modal.querySelector('[name="plan_id"]');picker.onchange=()=>{const p=data.plans.find(x=>x.id===picker.value);modal.querySelector('#plan-preview').textContent='套餐节点：'+nodeNames(p?.matched_node_ids||[]);};
 if(!u.is_admin)modal.querySelector('[name="quota_gb"]').step='any';
}

function nodeDetails(id){
 const n=data.nodes.find(x=>x.id===id),h=n.health;
 const protocols=h?.ports||JSON.parse(n.ports||'[]');
 const fresh=!!n.health_checked&&Date.now()/1000-n.health_checked<120;
 const rows=protocols.map(p=>{const known=fresh&&h&&p.listeners;const ok=known&&h.active&&Object.values(p.listeners).every(Boolean);const stateText=!known?'待采样':ok?'本机监听':'未监听';const transport=p.listeners?Object.keys(p.listeners).join('/').toUpperCase():'';return `<article class="protocol-tile"><div class="protocol-tile-head"><strong>${esc(p.protocol)}</strong><span class="status-dot ${!known?'unknown':ok?'good':'bad'}" aria-hidden="true"></span></div><small>${esc(transport)} ${esc(p.port)}</small><span class="protocol-state">${esc(stateText)}</span></article>`;}).join('');
 showModal(`<h2>${esc(n.name)} · 节点详情</h2>${n.state==='deleting'?'':`<div class="detail-toolbar">${btn('编辑名称与标签','node-edit',id)}</div>`}<div class="notice">${fresh?'以下为最近采样结果。':'采样尚无或已过期，请同步节点刷新。'}“监听”只表示本机端口存在，不代表云安全组、TLS、认证及外网连接均正常。健康检查不使用用户私密凭据。</div>`+
  meta('节点 IP / SSH 端口',(n.host==='local'?(h?.addresses?.join(', ')||'本机'):n.host)+' : '+n.ssh_port)+meta('连接域名',n.domain)+meta('核心版本',h?.version||n.version||'尚未采集')+meta('服务进程',h?(h.active?'运行中':'未运行'):'尚未采集')+
  meta('采样时间',n.health_checked?date(n.health_checked):'尚未采集')+meta('用户计量',n.stats_ready?'已通过接管验证':'未就绪')+meta('同步状态',n.status||'未知')+
  meta('已下发授权 / 应授权用户',n.assigned_user_count+' / '+n.desired_user_count)+meta('有历史流量的用户',n.historical_used_user_count)+meta('已记录累计流量',gb(n.recorded_traffic))+
  '<h3 class="section-title">部署协议与端口</h3><p>圆点表示最近采样的本机监听状态；不代表外网连接已验证。</p><div class="protocol-grid">'+ (rows||'<p>暂无协议记录，请同步节点。</p>')+'</div>'+
  '<h3 class="section-title">当前已下发授权的用户</h3>'+ (n.applied_users.map(u=>`<div class="meta"><span>${esc(u.name)}</span><strong>${esc(state(u.state))}</strong></div>`).join('')||'<p>暂无已下发用户。</p>')+
  '<p>已下发人数不是当前在线连接数；待撤销授权在节点同步成功前仍可能出现在这里。</p><div class="actions">'+
  `<button id="refresh-health">${n.state==='deleting'?'重试清理':'同步并刷新'}</button>`+
  (n.state==='deleting'?btn('服务器已释放 · 完成本地删除','node.forget',id,true):btn('更新 SNI','node-sni',id)+
    btn(n.state==='active'?'停用节点':'启用节点',n.state==='active'?'node.disable':'node.enable',id)+btn('删除节点','node.delete',id,true))+
  '<button data-close>关闭</button></div>');
 modal.querySelector('#refresh-health').onclick=()=>submit('node.sync',{id}).catch(e=>toast(e.message));
 modal.querySelectorAll('[data-action]').forEach(b=>b.onclick=()=>{closeModal();action(b.dataset.action,b.dataset.id);});
}

const previousAction=action;
action=function(a,id){if(a==='node-details')return nodeDetails(id);if(a==='user-edit')return editUser(id);return previousAction(a,id);};
const previousRender=render;
render=async function(){await previousRender();if(view==='plans'){root.querySelector('.heading p').textContent='指定节点或按标签匹配，用户可单独覆盖授权。';const cards=root.querySelectorAll('.grid > .card');cards.forEach((el,i)=>{const p=data.plans[i];if(!p)return;const box=document.createElement('div');box.innerHTML=meta('匹配模式',p.access_mode==='selected'?'指定节点':'标签匹配')+meta('套餐关联节点',nodeNames(p.matched_node_ids));el.querySelector('.actions').before(box);});}};
if(data.nodes)render();
