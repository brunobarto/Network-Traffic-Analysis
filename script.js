/* ================= DATA (simulated, realistic) ================= */
const DATA = {
  traffic: [212,188,176,642,598,160,190,340,780,920,960,1010,870,940,990,1020,960,880,610,420,360,300,260,230],
  proto: [["HTTPS",48],["DNS",14],["HTTP",9],["Other TCP",17],["Other UDP",9],["ICMP",3]],
  dns: [["update.microsoft.com",4210,0],["outlook.office365.com",3880,0],["cdn.cloudflare.net",2950,0],["x7k2q9pz.duckdns.org",2614,1],["login.salesforce.com",1730,0],["a3f9e1.tunnel-cdn.ru",1288,1]],
  http: [["200",16420],["30x",2210],["401",1370],["403",640],["404",980],["500",284]],
  tcp: [["SYN",41200],["SYN-ACK",33900],["ACK",96430],["FIN",29800],["RST",6420],["PSH",52100]],
  sev: [["Critical",4],["High",9],["Medium",15],["Low",9]],
  threats: [
    ["03:12:44","10.0.4.27","185.243.115.84",{en:"C2 Beaconing",fr:"Beaconing C2"},{en:"HTTPS every 60s ±2s, 1,412 sessions",fr:"HTTPS toutes les 60s ±2s, 1 412 sessions"},"critical"],
    ["03:18:02","10.0.4.27","a3f9e1.tunnel-cdn.ru",{en:"DNS Tunneling",fr:"Tunnel DNS"},{en:"TXT queries, 58-char subdomains, 1.9 MB out",fr:"Requêtes TXT, sous-domaines 58 car., 1,9 Mo sortants"},"critical"],
    ["03:41:19","10.0.4.27","91.215.42.10",{en:"Data Exfiltration",fr:"Exfiltration de données"},{en:"2.3 GB outbound outside office hours",fr:"2,3 Go sortants hors heures ouvrées"},"critical"],
    ["09:05:33","45.155.205.233","10.0.1.0/24",{en:"Port Scan",fr:"Scan de ports"},{en:"7,300 SYN without handshake, 1,024 ports",fr:"7 300 SYN sans handshake, 1 024 ports"},"high"],
    ["11:22:07","103.75.190.12","10.0.1.15:443 /login",{en:"Brute Force",fr:"Force brute"},{en:"1,370 HTTP 401 in 14 min",fr:"1 370 HTTP 401 en 14 min"},"high"],
    ["14:47:51","10.0.2.88","x7k2q9pz.duckdns.org",{en:"DGA Domain",fr:"Domaine DGA"},{en:"High-entropy domain, 2,614 queries",fr:"Domaine à forte entropie, 2 614 requêtes"},"critical"],
    ["16:09:12","10.0.3.41","198.51.100.23:80",{en:"Cleartext Credentials",fr:"Identifiants en clair"},{en:"HTTP POST with password field",fr:"HTTP POST avec champ mot de passe"},"medium"]
  ]
};

/* ================= I18N ================= */
const T = {
  en:{loading:"CHARGING PROJECT",tag:"CASE STUDY · SOC ANALYSIS · 24H CAPTURE",title:"Network Traffic Analysis & Threat Investigation",
    lead:"24 hours of corporate network traffic (≈1.28M packets) captured and analyzed. Goal: detect threats hidden in DNS, HTTP and TCP flows, and turn them into business decisions.",
    m1:"01 CAPTURE",m2:"02 ANALYZE",m3:"03 DETECT",m4:"04 ACT",k1:"Packets captured",k2:"DNS queries",k3:"HTTP requests",k4:"TCP sessions",k5:"Security alerts",k6:"Data volume (GB)",
    capTitle:"Live Packet Capture",capSub:"Simulated tcpdump/Wireshark stream. Flagged packets are highlighted.",pause:"PAUSE",resume:"RESUME",
    time:"Time",src:"Source",dst:"Destination",proto:"Proto",len:"Len",info:"Info",anTitle:"Traffic Analysis",hint:"▲ Click any chart for explanation",
    c1:"Bandwidth over 24h (Mbps)",c2:"Protocol mix",c3:"Top DNS domains (queries)",c4:"HTTP status codes",c5:"TCP flags distribution",c6:"Alerts by severity",
    thTitle:"Suspicious Activity Identified",type:"Threat",evidence:"Evidence",sev:"Severity",inTitle:"Business Insights",
    what:"WHAT IT SHOWS",find:"KEY FINDING",biz:"BUSINESS IMPACT",foot:"Built with HTML · CSS · JavaScript — simulated data for portfolio purposes.",
    suspicious:"SUSPICIOUS",sevNames:{Critical:"Critical",High:"High",Medium:"Medium",Low:"Low"},
    info_:{
      traffic:["Bandwidth over 24h","Network throughput per hour. Normal traffic follows office hours (08:00–18:00).","A 642 Mbps spike at 03:00, when nobody is working, coming from one workstation (10.0.4.27). That is 3.5× the night baseline.","Off-hours spikes are a classic exfiltration sign. 2.3 GB of possibly confidential data left the network: a potential GDPR fine of up to 4% of annual turnover."],
      proto:["Protocol mix","Share of each protocol in total packets.","HTTPS dominates (48%), which is healthy. But 9% is still unencrypted HTTP, and DNS (14%) is unusually high (normal is around 5–8%).","Unencrypted HTTP exposes credentials. Abnormal DNS volume pointed us to a tunneling channel used to bypass the firewall."],
      dns:["Top DNS domains","Most requested domain names. Red bars are flagged domains.","Two of the top 6 domains are malicious: a random-looking DuckDNS domain (DGA) and a .ru domain with long encoded subdomains (tunneling).","Blocking 2 domains at the DNS resolver cuts the attacker's command channel. Cost: close to zero. Value: the incident is contained."],
      http:["HTTP status codes","Server responses to HTTP requests: 2xx success, 3xx redirect, 4xx client error, 5xx server error.","1,370 '401 Unauthorized' responses, 94% of them from a single IP within 14 minutes: a brute-force attack on the login page.","Without rate limiting and MFA, one weak password gives full account takeover. Fix: lockout policy + MFA."],
      tcp:["TCP flags distribution","Count of TCP control flags. Normally every SYN gets a SYN-ACK.","7,300 more SYN than SYN-ACK, plus a high RST count. Connections are started and never completed: a port scan from 45.155.205.233.","Scans are reconnaissance: the attacker is mapping open services. Early detection lets us block them before exploitation."],
      sev:["Alerts by severity","The 37 alerts grouped by risk level.","13 alerts (35%) are Critical or High and all link back to 3 hosts. The other 24 are low-risk noise.","Prioritization: the SOC team focuses on 13 alerts instead of 37, cutting triage time by about 65%."]
    },
    ins:[["Compromised host","Workstation 10.0.4.27 shows beaconing, DNS tunneling and exfiltration. Isolate it now and reimage it.","2.3 GB at risk"],
      ["Quick win: DNS filtering","Blocking 2 malicious domains at the resolver stops command & control right away.","≈0 € cost"],
      ["Identity protection","Brute force on /login: enforce MFA and lockout after 5 failed attempts.","-99% takeover risk"],
      ["Alert prioritization","Correlating alerts by host cut the queue from 37 to 13 priority items.","-65% triage time"]]
  },
  fr:{loading:"CHARGEMENT DU PROJET",tag:"ÉTUDE DE CAS · ANALYSE SOC · CAPTURE 24H",title:"Analyse du trafic réseau & investigation des menaces",
    lead:"24 heures de trafic réseau d'entreprise (≈1,28M paquets) capturées et analysées. Objectif : détecter les menaces cachées dans les flux DNS, HTTP et TCP, et les traduire en décisions business.",
    m1:"01 CAPTURER",m2:"02 ANALYSER",m3:"03 DÉTECTER",m4:"04 AGIR",k1:"Paquets capturés",k2:"Requêtes DNS",k3:"Requêtes HTTP",k4:"Sessions TCP",k5:"Alertes sécurité",k6:"Volume (Go)",
    capTitle:"Capture de paquets en direct",capSub:"Flux tcpdump/Wireshark simulé. Les paquets suspects sont surlignés.",pause:"PAUSE",resume:"REPRENDRE",
    time:"Heure",src:"Source",dst:"Destination",proto:"Proto",len:"Taille",info:"Info",anTitle:"Analyse du trafic",hint:"▲ Cliquez sur un graphique pour l'explication",
    c1:"Bande passante sur 24h (Mbps)",c2:"Répartition des protocoles",c3:"Top domaines DNS (requêtes)",c4:"Codes de statut HTTP",c5:"Répartition des flags TCP",c6:"Alertes par sévérité",
    thTitle:"Activités suspectes identifiées",type:"Menace",evidence:"Preuve",sev:"Sévérité",inTitle:"Insights business",
    what:"CE QUE ÇA MONTRE",find:"CONSTAT CLÉ",biz:"IMPACT BUSINESS",foot:"Réalisé en HTML · CSS · JavaScript — données simulées pour portfolio.",
    suspicious:"SUSPECT",sevNames:{Critical:"Critique",High:"Élevée",Medium:"Moyenne",Low:"Faible"},
    info_:{
      traffic:["Bande passante sur 24h","Débit réseau par heure. Le trafic normal suit les heures de bureau (08h–18h).","Pic à 642 Mbps à 03h00, sans activité humaine, depuis un seul poste (10.0.4.27). C'est 3,5× la base nocturne.","Un pic hors horaires est un signe classique d'exfiltration. 2,3 Go de données potentiellement confidentielles sont sortis : risque d'amende RGPD jusqu'à 4% du CA annuel."],
      proto:["Répartition des protocoles","Part de chaque protocole dans le total des paquets.","HTTPS domine (48%), ce qui est sain. Mais 9% reste en HTTP non chiffré, et le DNS (14%) est anormalement élevé (normale : environ 5–8%).","Le HTTP non chiffré expose les identifiants. Le volume DNS anormal nous a menés à un tunnel qui contournait le pare-feu."],
      dns:["Top domaines DNS","Noms de domaine les plus demandés. Les barres rouges sont les domaines signalés.","2 des 6 premiers domaines sont malveillants : un domaine DuckDNS aléatoire (DGA) et un domaine .ru avec de longs sous-domaines encodés (tunnel).","Bloquer 2 domaines au résolveur DNS coupe le canal de l'attaquant. Coût : quasi nul. Valeur : l'incident est contenu."],
      http:["Codes de statut HTTP","Réponses serveur : 2xx succès, 3xx redirection, 4xx erreur client, 5xx erreur serveur.","1 370 réponses '401 Non autorisé', dont 94% depuis une seule IP en 14 minutes : attaque par force brute sur la page de connexion.","Sans limitation de débit ni MFA, un seul mot de passe faible suffit à prendre le contrôle d'un compte. Correctif : verrouillage + MFA."],
      tcp:["Répartition des flags TCP","Nombre de flags de contrôle TCP. Normalement, chaque SYN reçoit un SYN-ACK.","7 300 SYN de plus que de SYN-ACK, et beaucoup de RST. Des connexions sont ouvertes sans jamais aboutir : scan de ports depuis 45.155.205.233.","Le scan est une reconnaissance : l'attaquant cartographie les services ouverts. Le détecter tôt permet de bloquer avant l'exploitation."],
      sev:["Alertes par sévérité","Les 37 alertes classées par niveau de risque.","13 alertes (35%) sont Critiques ou Élevées et toutes renvoient à 3 machines. Les 24 autres sont du bruit à faible risque.","Priorisation : le SOC traite 13 alertes au lieu de 37, soit environ 65% de temps de tri en moins."]
    },
    ins:[["Poste compromis","Le poste 10.0.4.27 montre beaconing, tunnel DNS et exfiltration. À isoler tout de suite puis réinstaller.","2,3 Go à risque"],
      ["Gain rapide : filtrage DNS","Bloquer 2 domaines malveillants au résolveur stoppe immédiatement le command & control.","≈0 € de coût"],
      ["Protection des identités","Force brute sur /login : imposer la MFA et un verrouillage après 5 échecs.","-99% risque de piratage"],
      ["Priorisation des alertes","Corréler les alertes par machine fait passer la file de 37 à 13 priorités.","-65% temps de tri"]]
  }
};
let lang = "en";

/* ================= HELPERS ================= */
const $ = s => document.querySelector(s);
const css = v => getComputedStyle(document.body).getPropertyValue(v).trim();
const fmt = n => n.toLocaleString(lang === "fr" ? "fr-FR" : "en-US");

/* ================= LOADER ================= */
(function loader(){
  const cells = $("#cells");
  for (let i = 0; i < 20; i++) cells.appendChild(document.createElement("i"));
  let p = 0;
  const t = setInterval(() => {
    p = Math.min(100, p + Math.random() * 6 + 2);
    $("#pct").textContent = Math.floor(p);
    [...cells.children].forEach((c, i) => c.classList.toggle("on", i < Math.floor(p / 5)));
    if (p >= 100) {
      clearInterval(t);
      setTimeout(() => { $("#loader").classList.add("done"); countUp(); }, 350);
    }
  }, 70);
})();

function countUp(){
  document.querySelectorAll("[data-count]").forEach(el => {
    const end = parseFloat(el.dataset.count), dec = +el.dataset.dec || 0, t0 = performance.now();
    (function step(now){
      const k = Math.min(1, (now - t0) / 1400), e = 1 - Math.pow(1 - k, 3), v = end * e;
      el.textContent = dec ? v.toFixed(dec).replace(".", lang === "fr" ? "," : ".") : fmt(Math.round(v));
      if (k < 1) requestAnimationFrame(step);
    })(t0);
  });
}

/* ================= STARS ================= */
const sc = $("#stars"), sx = sc.getContext("2d");
let stars = [], mouse = { x: -999, y: -999 };
function initStars(){
  sc.width = innerWidth; sc.height = innerHeight;
  stars = Array.from({ length: Math.floor(innerWidth * innerHeight / 9000) }, () => ({
    x: Math.random() * sc.width, y: Math.random() * sc.height,
    r: Math.random() * 1.4 + .3, vx: (Math.random() - .5) * .2, vy: (Math.random() - .5) * .2, ox: 0, oy: 0
  }));
}
function drawStars(){
  sx.clearRect(0, 0, sc.width, sc.height);
  const ink = css("--ink"), acc = css("--accent");
  stars.forEach(s => {
    s.x += s.vx; s.y += s.vy;
    if (s.x < 0) s.x = sc.width; if (s.x > sc.width) s.x = 0;
    if (s.y < 0) s.y = sc.height; if (s.y > sc.height) s.y = 0;
    const dx = s.x + s.ox - mouse.x, dy = s.y + s.oy - mouse.y, d = Math.hypot(dx, dy);
    if (d < 120) { const f = (120 - d) / 120 * 2.2; s.ox += dx / d * f; s.oy += dy / d * f; }
    s.ox *= .93; s.oy *= .93;
    sx.globalAlpha = d < 120 ? .9 : .45;
    sx.fillStyle = d < 120 ? acc : ink;
    sx.fillRect(s.x + s.ox, s.y + s.oy, s.r * 1.6, s.r * 1.6); // square stars = discrete geometry
  });
  sx.globalAlpha = 1;
  requestAnimationFrame(drawStars);
}
addEventListener("mousemove", e => { mouse.x = e.clientX; mouse.y = e.clientY; });
addEventListener("resize", () => { initStars(); drawAll(); });
initStars(); drawStars();

/* ================= CHARTS ================= */
function setup(cv){
  const r = cv.getBoundingClientRect(), d = devicePixelRatio || 1;
  cv.width = r.width * d; cv.height = r.height * d;
  const c = cv.getContext("2d"); c.scale(d, d);
  c.font = "600 12px Inconsolata"; cv._hits = [];
  return { c, w: r.width, h: r.height };
}
const palette = () => [css("--accent"), css("--blue"), css("--yellow"), css("--ink"), css("--muted"), css("--ok")];

function lineChart(cv, vals){
  const { c, w, h } = setup(cv), p = 36, max = 1100, ink = css("--ink"), mut = css("--muted"), acc = css("--accent");
  c.strokeStyle = mut; c.fillStyle = mut; c.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = h - p - (h - 2 * p) * i / 4;
    c.globalAlpha = .25; c.beginPath(); c.moveTo(p, y); c.lineTo(w - 10, y); c.stroke(); c.globalAlpha = 1;
    c.fillText(max * i / 4, 2, y + 4);
  }
  const X = i => p + (w - p - 20) * i / 23, Y = v => h - p - (h - 2 * p) * v / max;
  // night threshold
  c.setLineDash([6, 4]); c.strokeStyle = acc; c.beginPath(); c.moveTo(p, Y(450)); c.lineTo(w - 10, Y(450)); c.stroke(); c.setLineDash([]);
  // area
  c.beginPath(); c.moveTo(X(0), Y(0)); vals.forEach((v, i) => c.lineTo(X(i), Y(v))); c.lineTo(X(23), Y(0));
  c.fillStyle = acc; c.globalAlpha = .12; c.fill(); c.globalAlpha = 1;
  // stepped line (discrete)
  c.beginPath(); c.strokeStyle = ink; c.lineWidth = 2.5;
  vals.forEach((v, i) => { i ? (c.lineTo(X(i), Y(vals[i - 1])), c.lineTo(X(i), Y(v))) : c.moveTo(X(i), Y(v)); });
  c.stroke();
  vals.forEach((v, i) => {
    const anom = (i < 7 && v > 450);
    c.fillStyle = anom ? acc : ink;
    const s = anom ? 10 : 6; c.fillRect(X(i) - s / 2, Y(v) - s / 2, s, s);
    if (i % 3 === 0) { c.fillStyle = mut; c.fillText(String(i).padStart(2, "0") + "h", X(i) - 8, h - 12); }
    cv._hits.push({ x: X(i) - 8, y: Y(v) - 8, w: 16, h: 16, t: `${String(i).padStart(2, "0")}:00 → ${v} Mbps${anom ? " ⚠" : ""}` });
  });
}

function donut(cv, data, unit){
  const { c, w, h } = setup(cv), cols = palette(), total = data.reduce((a, b) => a + b[1], 0);
  const cx = Math.min(w * .35, h / 2 + 10), cy = h / 2, R = Math.min(h / 2 - 10, w * .3), r = R * .55;
  let a = -Math.PI / 2;
  data.forEach(([l, v], i) => {
    const s = v / total * Math.PI * 2;
    c.beginPath(); c.moveTo(cx, cy); c.arc(cx, cy, R, a, a + s); c.closePath();
    c.fillStyle = cols[i % cols.length]; c.fill();
    c.strokeStyle = css("--panel"); c.lineWidth = 3; c.stroke();
    a += s;
    const ly = 20 + i * 22, lx = cx + R + 24;
    c.fillRect(lx, ly - 9, 12, 12);
    c.fillStyle = css("--ink");
    const name = T[lang].sevNames[l] || l;
    c.fillText(`${name} ${unit === "%" ? v + "%" : v}`, lx + 18, ly + 1);
    cv._hits.push({ x: lx, y: ly - 12, w: 140, h: 18, t: `${name}: ${unit === "%" ? v + "%" : v + " (" + Math.round(v / total * 100) + "%)"}` });
  });
  c.beginPath(); c.arc(cx, cy, r, 0, Math.PI * 2); c.fillStyle = css("--panel"); c.fill();
  c.fillStyle = css("--ink"); c.font = "900 20px Inconsolata"; c.textAlign = "center";
  c.fillText(unit === "%" ? "100%" : total, cx, cy + 7); c.textAlign = "left";
}

function vbars(cv, data, flagFn){
  const { c, w, h } = setup(cv), p = 30, max = Math.max(...data.map(d => d[1])) * 1.1, bw = (w - p) / data.length;
  data.forEach(([l, v], i) => {
    const bh = (h - 2 * p) * v / max, x = p + i * bw + bw * .18, y = h - p - bh;
    const flag = flagFn(l, v);
    c.fillStyle = flag ? css("--accent") : css("--ink"); c.fillRect(x, y, bw * .64, bh);
    c.fillStyle = css("--muted"); c.fillText(l, x, h - 10);
    c.fillStyle = css("--ink"); c.fillText(v >= 10000 ? (v / 1000).toFixed(1) + "k" : v, x, y - 6);
    cv._hits.push({ x, y, w: bw * .64, h: bh, t: `${l}: ${fmt(v)}${flag ? " ⚠ " + T[lang].suspicious : ""}` });
  });
}

function hbars(cv, data){
  const { c, w, h } = setup(cv), max = data[0][1] * 1.15, rowH = (h - 10) / data.length;
  data.forEach(([l, v, f], i) => {
    const y = 5 + i * rowH, bw = (w - 10) * v / max;
    c.fillStyle = f ? css("--accent") : css("--blue"); c.globalAlpha = f ? 1 : .85;
    c.fillRect(0, y + rowH * .45, bw, rowH * .4); c.globalAlpha = 1;
    c.fillStyle = f ? css("--accent") : css("--ink");
    c.fillText(`${f ? "⚠ " : ""}${l}  ${fmt(v)}`, 0, y + rowH * .38);
    cv._hits.push({ x: 0, y, w: Math.max(bw, 200), h: rowH, t: `${l}: ${fmt(v)}${f ? " ⚠ " + T[lang].suspicious : ""}` });
  });
}

function drawAll(){
  lineChart($("#cTraffic"), DATA.traffic);
  donut($("#cProto"), DATA.proto, "%");
  hbars($("#cDns"), DATA.dns);
  vbars($("#cHttp"), DATA.http, l => l === "401");
  vbars($("#cTcp"), DATA.tcp, l => l === "SYN" || l === "RST");
  donut($("#cSev"), DATA.sev, "n");
}

/* tooltip on hover */
const tip = $("#tip");
document.querySelectorAll(".card canvas").forEach(cv => {
  cv.addEventListener("mousemove", e => {
    const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    const hit = (cv._hits || []).find(b => x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h);
    if (hit) { tip.textContent = hit.t; tip.style.left = e.clientX + "px"; tip.style.top = e.clientY + "px"; tip.style.opacity = 1; }
    else tip.style.opacity = 0;
  });
  cv.addEventListener("mouseleave", () => tip.style.opacity = 0);
});

/* ================= MODAL ================= */
document.querySelectorAll(".card").forEach(card => card.addEventListener("click", () => {
  const [t, w, f, b] = T[lang].info_[card.dataset.info];
  $("#mTitle").textContent = t; $("#mWhat").textContent = w; $("#mFind").textContent = f; $("#mBiz").textContent = b;
  $("#modal").classList.add("open");
}));
$("#mClose").onclick = () => $("#modal").classList.remove("open");
$("#modal").onclick = e => { if (e.target.id === "modal") $("#modal").classList.remove("open"); };
addEventListener("keydown", e => { if (e.key === "Escape") $("#modal").classList.remove("open"); });

/* ================= LIVE CAPTURE ================= */
let pktN = 1284620, running = true;
const normal = [
  () => ["10.0.2." + rnd(10, 120), "142.250.74." + rnd(1, 250), "TLS", rnd(60, 1500), "Application Data"],
  () => ["10.0.3." + rnd(10, 120), "10.0.0.53", "DNS", rnd(70, 110), "Standard query A outlook.office365.com"],
  () => ["10.0.1." + rnd(10, 120), "104.16.85." + rnd(1, 250), "TCP", 66, "443 → " + rnd(49152, 65535) + " [ACK]"],
  () => ["10.0.2." + rnd(10, 120), "93.184.216.34", "HTTP", rnd(300, 900), "GET /index.html HTTP/1.1"],
  () => ["10.0.4." + rnd(10, 120), "10.0.0.53", "DNS", 92, "Standard query response A cdn.cloudflare.net"]
];
const bad = [
  () => ["10.0.4.27", "10.0.0.53", "DNS", 214, "TXT " + Math.random().toString(36).slice(2, 14) + ".a3f9e1.tunnel-cdn.ru"],
  () => ["45.155.205.233", "10.0.1." + rnd(1, 254), "TCP", 54, rnd(1, 1024) + " [SYN] no reply"],
  () => ["103.75.190.12", "10.0.1.15", "HTTP", 412, "POST /login → 401 Unauthorized"],
  () => ["10.0.4.27", "185.243.115.84", "TLS", 318, "Beacon interval 60s (C2)"]
];
function rnd(a, b){ return Math.floor(Math.random() * (b - a + 1)) + a; }
function addPacket(){
  if (!running) return;
  const isBad = Math.random() < .22, p = (isBad ? bad : normal)[rnd(0, (isBad ? bad : normal).length - 1)]();
  const d = new Date(), tm = d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0");
  const tr = document.createElement("tr"); if (isBad) tr.className = "flag";
  tr.innerHTML = `<td>${++pktN}</td><td>${tm}</td><td>${p[0]}</td><td>${p[1]}</td><td>${p[2]}</td><td>${p[3]}</td><td>${p[4]}</td>`;
  const body = $("#capBody"); body.prepend(tr);
  while (body.children.length > 10) body.lastChild.remove();
}
setInterval(addPacket, 700);
for (let i = 0; i < 8; i++) addPacket();
$("#capBtn").onclick = () => {
  running = !running;
  $("#capBtn").dataset.i18n = running ? "pause" : "resume";
  $("#capBtn").textContent = T[lang][running ? "pause" : "resume"];
};

/* ================= TABLE + INSIGHTS ================= */
function renderThreats(){
  $("#thBody").innerHTML = DATA.threats.map(r => {
    const sevKey = r[5][0].toUpperCase() + r[5].slice(1);
    return `<tr><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td><td><strong>${r[3][lang]}</strong></td><td>${r[4][lang]}</td><td><span class="badge b-${r[5]}">${T[lang].sevNames[sevKey]}</span></td></tr>`;
  }).join("");
}
function renderInsights(){
  $("#insights").innerHTML = T[lang].ins.map(([t, d, v]) =>
    `<div class="ins"><div class="shape"></div><div><h5>${t}</h5><p>${d}</p><span class="val">${v}</span></div></div>`).join("");
}

/* ================= LANGUAGE ================= */
function applyLang(){
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach(el => { const v = T[lang][el.dataset.i18n]; if (typeof v === "string") el.textContent = v; });
  $("#langBtn").textContent = lang === "en" ? "FR" : "EN";
  renderThreats(); renderInsights(); drawAll();
  document.querySelectorAll("[data-count]").forEach(el => {
    const v = parseFloat(el.dataset.count), dec = +el.dataset.dec || 0;
    if (el.textContent !== "0") el.textContent = dec ? v.toFixed(dec).replace(".", lang === "fr" ? "," : ".") : fmt(v);
  });
}
$("#langBtn").onclick = () => { lang = lang === "en" ? "fr" : "en"; localStorage.setItem("ns-lang", lang); applyLang(); };

/* ================= THEME + ACCENT ================= */
$("#themeBtn").onclick = () => {
  document.body.classList.toggle("light");
  localStorage.setItem("ns-theme", document.body.classList.contains("light") ? "light" : "dark");
  drawAll();
};
function setAccent(c){
  document.documentElement.style.setProperty("--accent", c);
  document.body.style.setProperty("--accent", c);
  document.querySelectorAll(".sw").forEach(s => s.classList.toggle("active", s.dataset.c === c));
  $("#picker").value = c; localStorage.setItem("ns-accent", c); drawAll();
}
document.querySelectorAll(".sw[data-c]").forEach(s => s.onclick = () => setAccent(s.dataset.c));
$("#picker").oninput = e => setAccent(e.target.value);

/* ================= INIT ================= */
if (localStorage.getItem("ns-theme") === "light") document.body.classList.add("light");
lang = localStorage.getItem("ns-lang") || "en";
document.fonts.ready.then(() => {
  applyLang();
  setAccent(localStorage.getItem("ns-accent") || "#e63946");
});
