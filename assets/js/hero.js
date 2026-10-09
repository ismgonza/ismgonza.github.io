// Fondo animado del hero. Modo en <canvas data-mode="network|scan">
(function () {
  var cv = document.getElementById('hero-canvas');
  if (!cv) return;
  var ctx = cv.getContext('2d'), W, H, dpr, mode = cv.dataset.mode || 'network';
  var still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var RED = '239,68,68', GREEN = '16,185,129', CYAN = cv.dataset.color || '125,211,252';

  function size() {
    var r = cv.parentNode.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width; H = r.height;
    cv.width = W * dpr; cv.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    init();
  }
  // Más fuerte a la derecha, suave detrás del texto
  function side(x) { return 0.25 + 0.75 * Math.min(1, x / W * 1.3); }

  /* ---------- B: red de nodos ---------- */
  var nodes = [], mouse = { x: -999, y: -999 };
  function initNetwork() {
    var n = Math.round(Math.min(120, W * H / 8000));
    nodes = [];
    for (var i = 0; i < n; i++) nodes.push({
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - .5) * .3, vy: (Math.random() - .5) * .3,
      r: 1.2 + Math.random() * 1.6, s: 0, t: 0 // s: 0 normal, 1 riesgo, 2 protegido
    });
  }
  function drawNetwork(now) {
    ctx.clearRect(0, 0, W, H);
    var D = Math.min(150, W / 7);
    // cada ~0.9 s un nodo entra en riesgo; 1.6 s después queda protegido
    if (!still && now - (drawNetwork.last || 0) > 900) {
      drawNetwork.last = now;
      var k = nodes[Math.floor(Math.random() * nodes.length)];
      if (k.s === 0) { k.s = 1; k.t = now; }
    }
    for (var i = 0; i < nodes.length; i++) {
      var a = nodes[i];
      if (!still) {
        a.x += a.vx; a.y += a.vy;
        if (a.x < 0 || a.x > W) a.vx *= -1;
        if (a.y < 0 || a.y > H) a.vy *= -1;
      }
      if (a.s === 1 && now - a.t > 1600) { a.s = 2; a.t = now; }
      if (a.s === 2 && now - a.t > 2600) a.s = 0;
      for (var j = i + 1; j < nodes.length; j++) {
        var b = nodes[j], dx = a.x - b.x, dy = a.y - b.y, d = Math.sqrt(dx * dx + dy * dy);
        if (d < D) {
          var col = a.s === 1 || b.s === 1 ? RED : a.s === 2 || b.s === 2 ? GREEN : '255,255,255';
          var al = (1 - d / D) * (col === '255,255,255' ? .24 : .5) * side((a.x + b.x) / 2);
          ctx.strokeStyle = 'rgba(' + col + ',' + al + ')'; ctx.lineWidth = 1;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
      var md = Math.hypot(a.x - mouse.x, a.y - mouse.y);
      if (md < D * 1.2) {
        ctx.strokeStyle = 'rgba(' + CYAN + ',' + (1 - md / (D * 1.2)) * .5 + ')';
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke();
      }
    }
    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      var c = a.s === 1 ? RED : a.s === 2 ? GREEN : '255,255,255', sd = side(a.x);
      if (a.s) { // anillo que se expande
        var p = (now - a.t) / (a.s === 1 ? 1600 : 2600);
        ctx.strokeStyle = 'rgba(' + c + ',' + (1 - p) * .8 * sd + ')';
        ctx.beginPath(); ctx.arc(a.x, a.y, 4 + p * 18, 0, 7); ctx.stroke();
      }
      ctx.fillStyle = 'rgba(' + c + ',' + (a.s ? .95 : .75) * sd + ')';
      ctx.beginPath(); ctx.arc(a.x, a.y, a.s ? a.r + 1.5 : a.r, 0, 7); ctx.fill();
    }
  }

  /* ---------- C: escáner ---------- */
  var icons = [], G = 44, SWEEP = 7000;
  function initScan() {
    var kinds = ['lock', 'cloud', 'chip', 'shield', 'key', 'cloud', 'lock', 'chip'];
    var spots = [[.62, .25], [.78, .18], [.9, .4], [.7, .55], [.84, .72], [.58, .8], [.95, .85], [.5, .45]];
    icons = spots.map(function (p, i) {
      return { x: Math.round(p[0] * W / G) * G, y: Math.round(p[1] * H / G) * G, k: kinds[i], hit: -1e9 };
    }).filter(function (ic) { return W > 700 || ic.x > W * .55; });
  }
  function icon(k, x, y, al) {
    ctx.save(); ctx.translate(x, y);
    ctx.strokeStyle = 'rgba(' + CYAN + ',' + al + ')'; ctx.lineWidth = 2; ctx.lineJoin = ctx.lineCap = 'round';
    ctx.beginPath();
    if (k === 'lock') { ctx.rect(-10, -2, 20, 15); ctx.moveTo(-6, -2); ctx.arc(0, -6, 6, Math.PI, 0); ctx.lineTo(6, -2); }
    if (k === 'cloud') { ctx.arc(-6, 3, 6, Math.PI * .5, Math.PI * 1.5); ctx.arc(1, -3, 8, Math.PI * 1.1, Math.PI * 1.9); ctx.arc(8, 3, 6, Math.PI * 1.5, Math.PI * .5); ctx.closePath(); }
    if (k === 'chip') { ctx.rect(-9, -9, 18, 18); ctx.rect(-4, -4, 8, 8); [-5, 0, 5].forEach(function (o) { ctx.moveTo(o, -9); ctx.lineTo(o, -14); ctx.moveTo(o, 9); ctx.lineTo(o, 14); ctx.moveTo(-9, o); ctx.lineTo(-14, o); ctx.moveTo(9, o); ctx.lineTo(14, o); }); }
    if (k === 'shield') { ctx.moveTo(0, -13); ctx.lineTo(11, -8); ctx.lineTo(10, 3); ctx.quadraticCurveTo(7, 10, 0, 14); ctx.quadraticCurveTo(-7, 10, -10, 3); ctx.lineTo(-11, -8); ctx.closePath(); ctx.moveTo(-4, 0); ctx.lineTo(-1, 4); ctx.lineTo(5, -4); }
    if (k === 'key') { ctx.arc(-6, 0, 6, 0, 7); ctx.moveTo(0, 0); ctx.lineTo(14, 0); ctx.moveTo(10, 0); ctx.lineTo(10, 5); ctx.moveTo(14, 0); ctx.lineTo(14, 4); }
    ctx.stroke(); ctx.restore();
  }
  function drawScan(now) {
    ctx.clearRect(0, 0, W, H);
    var sx = still ? W * .75 : ((now % SWEEP) / SWEEP) * (W + 200) - 100;
    // cuadrícula: se ilumina cerca de la línea
    for (var x = 0; x <= W; x += G) {
      var near = Math.max(0, 1 - Math.abs(x - sx) / 160);
      ctx.strokeStyle = 'rgba(255,255,255,' + (.05 + near * .18) * side(x) + ')';
      ctx.beginPath(); ctx.moveTo(x + .5, 0); ctx.lineTo(x + .5, H); ctx.stroke();
    }
    for (var y = 0; y <= H; y += G) {
      ctx.strokeStyle = 'rgba(255,255,255,.05)';
      ctx.beginPath(); ctx.moveTo(0, y + .5); ctx.lineTo(W, y + .5); ctx.stroke();
    }
    // puntos en las intersecciones cercanas a la línea
    for (x = 0; x <= W; x += G) {
      var nr = Math.max(0, 1 - Math.abs(x - sx) / 90);
      if (nr > 0) for (y = 0; y <= H; y += G) {
        ctx.fillStyle = 'rgba(' + CYAN + ',' + nr * .7 * side(x) + ')';
        ctx.fillRect(x - 1, y - 1, 3, 3);
      }
    }
    // línea de escaneo con brillo
    var gr = ctx.createLinearGradient(sx - 120, 0, sx, 0);
    gr.addColorStop(0, 'rgba(' + CYAN + ',0)'); gr.addColorStop(1, 'rgba(' + CYAN + ',' + .14 * side(sx) + ')');
    ctx.fillStyle = gr; ctx.fillRect(sx - 120, 0, 120, H);
    ctx.fillStyle = 'rgba(' + CYAN + ',' + .8 * side(sx) + ')'; ctx.fillRect(sx - 1, 0, 2, H);
    // íconos: se encienden cuando pasa la línea y se apagan despacio
    icons.forEach(function (ic) {
      if (Math.abs(ic.x - sx) < 6) ic.hit = now;
      var age = still ? 0 : (now - ic.hit) / 2500, al = Math.max(.22, 1 - age) * (W < 700 ? .5 : 1);
      if (age < 1) {
        ctx.fillStyle = 'rgba(' + CYAN + ',' + (1 - age) * .12 + ')';
        ctx.beginPath(); ctx.arc(ic.x, ic.y, 26, 0, 7); ctx.fill();
      }
      icon(ic.k, ic.x, ic.y, al);
    });
  }

  function init() { mode === 'scan' ? initScan() : initNetwork(); }
  function frame(now) { (mode === 'scan' ? drawScan : drawNetwork)(now); if (!still) requestAnimationFrame(frame); }

  var host = cv.closest('.hero-section') || cv.parentNode;
  host.addEventListener('mousemove', function (e) { var r = cv.getBoundingClientRect(); mouse.x = e.clientX - r.left; mouse.y = e.clientY - r.top; });
  host.addEventListener('mouseleave', function () { mouse.x = mouse.y = -999; });
  window.addEventListener('resize', size);
  window.heroMode = function (m) { mode = m; init(); }; // solo para la vista previa
  size(); requestAnimationFrame(frame);
})();
