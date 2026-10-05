---
layout: post
published: true
title: "Tu Gmail sin SMS: cómo protegerte del cambio de chip (SIM swap)"
description: "Passkey, verificación en dos pasos y cómo quitar el SMS de tu cuenta de Google, paso a paso y explicado simple."
date: 2026-10-05 09:00
author: Isma Gonzalez
categories: security
tags: [gmail, passkeys, sim swap, verificación en dos pasos, ciberseguridad]
duration:
banner_image:
banner_image_credits:
---
<style>
.pd-guide{--navy:#0F2A47;--acc:#1F8A70;--light:#EEF4F2;--warn:#FFF4E0;--warnb:#E0A030;--grey:#5A6470;--line:#D8DEE4;color:#1B1F24}
.pd-guide h2{color:var(--navy)}
.pd-box{background:var(--light);border-left:4px solid var(--acc);padding:14px 18px;margin:18px 0;border-radius:0 6px 6px 0}
.pd-box.warn{background:var(--warn);border-left-color:var(--warnb)}
.pd-box p{margin:0 0 8px}.pd-box p:last-child{margin:0}
.pd-acc{border:1px solid var(--line);border-radius:8px;margin:10px 0;background:#fff;overflow:hidden}
.pd-acc summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;padding:14px 18px;font-weight:700;color:var(--navy)}
.pd-acc summary::-webkit-details-marker{display:none}
.pd-acc summary:focus-visible{outline:3px solid var(--acc);outline-offset:-3px}
.pd-acc summary .pd-title{flex:1}
.pd-acc summary .pd-count{font-size:.8em;font-weight:600;color:var(--grey);background:var(--light);padding:2px 10px;border-radius:99px;white-space:nowrap}
.pd-acc.done summary .pd-count{background:var(--acc);color:#fff}
.pd-acc summary::after{content:"";width:9px;height:9px;border-right:2px solid var(--acc);border-bottom:2px solid var(--acc);transform:rotate(45deg);transition:transform .2s}
.pd-acc[open] summary::after{transform:rotate(-135deg)}
.pd-acc[open] summary{border-bottom:1px solid var(--line)}
.pd-list{list-style:none;margin:0;padding:6px 18px 12px}
.pd-list li{border-bottom:1px solid var(--line);padding:10px 0}
.pd-list li:last-child{border-bottom:0}
.pd-list label{display:flex;gap:12px;cursor:pointer;line-height:1.5}
.pd-list input{accent-color:var(--acc);width:18px;height:18px;margin-top:3px;flex-shrink:0}
.pd-list input:checked + span{color:var(--grey)}
.pd-ref{display:block;font-size:.78em;color:var(--acc);margin-top:2px}
.pd-table{width:100%;border-collapse:collapse;font-size:.92em;margin:12px 0}
.pd-guide .pd-table thead th{background:#EEF4F2;color:#000;text-align:left;padding:8px 10px}
.pd-guide .pd-table th:nth-child(2),.pd-guide .pd-table td:nth-child(2){white-space:nowrap}
.pd-table td{padding:8px 10px;border:1px solid var(--line);vertical-align:top}
.pd-table tr:nth-child(even) td{background:var(--light)}
.pd-scroll{overflow-x:auto}
.pd-small{font-size:.82em;color:var(--grey)}
.pd-guide code{background:var(--light);border:1px solid var(--line);border-radius:4px;padding:1px 6px;font-size:.9em;color:var(--navy)}
@media (prefers-reduced-motion:reduce){.pd-acc summary::after{transition:none}}
</style>

<div class="pd-guide" markdown="1">

Si llegaste desde el reel de Instagram: ya creaste tu llave de acceso (o estás por hacerlo). Esta guía cubre lo que no cabía en 60 segundos: **cómo sacar el SMS de la ecuación** para que el cambio de chip no le sirva a nadie.

## Lo básico en 1 minuto

En el **SIM swap**, alguien convence a tu operadora de pasar tu número a otro chip. Desde ese momento, los mensajes de texto le llegan a él. Si tu Gmail se protege con un código por SMS, ese código también.

Formas de confirmar que sos vos, de mejor a peor:

<div class="pd-scroll">
<table class="pd-table">
<thead><tr><th>Método</th><th>Cambio de chip</th><th>Página falsa</th></tr></thead>
<tbody>
<tr><td><strong>Llave de acceso (passkey)</strong></td><td>✅ No le sirve</td><td>✅ No le sirve</td></tr>
<tr><td><strong>Mensaje de Google</strong> en tu celular</td><td>✅ No le sirve</td><td>⚠️ Podés aprobar sin darte cuenta</td></tr>
<tr><td><strong>App autenticadora</strong> (código de 6 dígitos)</td><td>✅ No le sirve</td><td>⚠️ Podés escribir el código en la página falsa</td></tr>
<tr><td><strong>Código por SMS</strong></td><td>❌ Le llega a él</td><td>❌ Le sirve</td></tr>
</tbody>
</table>
</div>

<div class="pd-box warn">
<p><strong>Ojo:</strong> crear la llave de acceso no alcanza si el SMS sigue activo. Al iniciar sesión, el atacante toca <strong>"Probar otro método"</strong>, elige el mensaje de texto y listo. Por eso el último paso es quitarlo.</p>
</div>

## Checklist

Hacelo en este orden. Primero agregás opciones seguras, al final quitás el SMS. Así nunca te quedás afuera de tu propia cuenta.

<p class="pd-small">Ruta base en el celular: Gmail → tu foto de perfil → <strong>Administrar tu Cuenta de Google</strong> → <strong>Seguridad y acceso</strong>. Los nombres de los menús pueden cambiar un poco según tu versión.</p>

</div>

<div class="pd-guide">
<details class="pd-acc"><summary><span class="pd-title">1. Creá tu llave de acceso</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>En <strong>Seguridad y acceso</strong>, entraste a <strong>Llaves de acceso y llaves de seguridad</strong> y tocaste <strong>Crear una llave de acceso</strong>. Confirmaste con tu huella, cara o PIN.<span class="pd-ref">Google · FIDO Alliance</span></span></label></li>
<li><label><input type="checkbox"><span>Si te apareció <strong>"¿Aprobar esta llave de acceso?"</strong>, es normal: Google pone una espera de seguridad a las llaves nuevas. Podés aprobarla con otra llave que ya tengas o esperar.<span class="pd-ref">Google</span></span></label></li>
<li><label><input type="checkbox"><span>Sabés dónde quedó guardada: en <strong>iPhone</strong>, en la app <strong>Contraseñas</strong>; en <strong>Android</strong>, en el <strong>Gestor de contraseñas de Google</strong> (algunos Samsung ofrecen Samsung Pass). Si cambiás de celular, se recupera con esa misma cuenta.<span class="pd-ref">Apple · Google</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">2. Activá la verificación en 2 pasos</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>En <strong>Seguridad y acceso → Verificación en 2 pasos</strong>, la activaste. Si está apagada, a alguien le basta tu contraseña para entrar: la llave de acceso es una puerta más segura, pero la puerta vieja sigue abierta.<span class="pd-ref">Google · NIST · CISA</span></span></label></li>
<li><label><input type="checkbox"><span>Dejaste tu llave de acceso como segundo paso. Google la acepta así.<span class="pd-ref">Google</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">3. Agregá segundos pasos que no sean SMS</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Activaste el <strong>Mensaje de Google</strong>: al iniciar sesión te llega un aviso en tu celular y tocás "Sí, soy yo". Leé siempre desde dónde es el intento antes de aprobar.<span class="pd-ref">Google</span></span></label></li>
<li><label><input type="checkbox"><span>Opcional: agregaste una <strong>app autenticadora</strong> (Google o Microsoft Authenticator) como respaldo.<span class="pd-ref">NIST · Google</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">4. Guardá tus códigos de respaldo</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>En <strong>Verificación en 2 pasos → Códigos de respaldo</strong>, generaste tus códigos. Sirven una sola vez cada uno y te salvan si perdés el celular.<span class="pd-ref">Google</span></span></label></li>
<li><label><input type="checkbox"><span>Los guardaste en tu gestor de contraseñas o impresos en un lugar seguro. <strong>No</strong> en tu mismo correo ni en una foto del celular.<span class="pd-ref">Google</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">5. Quitá el SMS</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Antes de quitarlo, comprobaste que tenés al menos dos opciones de los pasos 1 a 4: llave de acceso, Mensaje de Google, autenticadora o códigos de respaldo.</span></label></li>
<li><label><input type="checkbox"><span>En <strong>Verificación en 2 pasos</strong>, buscaste la sección de <strong>números de teléfono</strong> y eliminaste tu número como segundo paso.<span class="pd-ref">Google · NIST SP 800-63B</span></span></label></li>
<li><label><input type="checkbox"><span>Cerraste sesión y probaste entrar de nuevo para confirmar que ya no te ofrece el SMS.</span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">6. Revisá tus datos de recuperación</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Tu <strong>correo de recuperación</strong> está al día y es una cuenta que también tiene llave de acceso o verificación en 2 pasos. Si ese correo es débil, se vuelve la puerta trasera.<span class="pd-ref">Google</span></span></label></li>
<li><label><input type="checkbox"><span>Sabés que el <strong>teléfono de recuperación</strong> también recibe SMS. Si lo dejás, le preguntaste a tu operadora si puede ponerle un <strong>PIN o bloqueo a los cambios de chip</strong> de tu línea.<span class="pd-ref">FTC</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">7. Si pasa algo raro</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Sabés la señal clásica: tu celular marca <strong>"Sin servicio"</strong> de la nada, en un lugar donde siempre tenés señal. Llamás a tu operadora de inmediato desde otro teléfono.<span class="pd-ref">FTC</span></span></label></li>
<li><label><input type="checkbox"><span>Si perdés el celular: entrás con un código de respaldo, revisás <strong>Tus dispositivos</strong> en Seguridad y acceso y cerrás la sesión del celular perdido.<span class="pd-ref">Google</span></span></label></li>
<li><label><input type="checkbox"><span>Si te llega un aviso de inicio de sesión que no fuiste vos: cambiás la contraseña y revisás que tu correo no esté reenviando mensajes a otra dirección.</span></label></li>
</ul></details>
</div>

<div class="pd-guide" markdown="1">

## Empezá hoy: 4 acciones rápidas

1. Creá tu llave de acceso (como en el reel).
2. Activá la verificación en 2 pasos y el Mensaje de Google.
3. Generá y guardá tus códigos de respaldo.
4. Quitá tu número de teléfono como segundo paso.

Son unos 10 minutos. Después, un cambio de chip ya no te deja sin correo.

<div class="pd-box">
<p><strong>¿Querés el nivel máximo?</strong> Si manejás dinero, datos de clientes o sos figura pública, mirá el <a href="https://landing.google.com/advancedprotection/">Programa de Protección Avanzada de Google</a>: exige llave de acceso o llave física para todo.</p>
<p>Y si querés ordenar el resto de tus claves (frases, gestor, equipo), está la <a href="/security/2026/09/26/passkeys-frases-contrasenas.html">guía completa de passkeys y contraseñas</a>.</p>
</div>

<div class="pd-box">
<p><strong>¿Te trabaste en algún paso?</strong> Escribime por Instagram a <a href="https://instagram.com/ismagonrod"><strong>@ismagonrod</strong></a> y lo vemos.</p>
</div>

<p class="pd-small"><strong>Fuentes:</strong> <a href="https://support.google.com/accounts/answer/185839">Google: Activar la verificación en 2 pasos</a> · <a href="https://support.google.com/accounts/answer/1187538">Google: Códigos de respaldo</a> · <a href="https://g.co/passkeys">Google: Llaves de acceso</a> · <a href="https://pages.nist.gov/800-63-4/sp800-63b.html">NIST SP 800-63B</a> · <a href="https://www.cisa.gov/secure-our-world/turn-mfa">CISA: Turn On MFA</a> · <a href="https://consumer.ftc.gov/articles/sim-swap-scams-how-protect-yourself">FTC: SIM swap scams</a> · <a href="https://fidoalliance.org/passkeys/">FIDO Alliance: Passkeys</a>.</p>

</div>

<script>
document.querySelectorAll('.pd-acc').forEach(function (acc) {
  var boxes = acc.querySelectorAll('input[type="checkbox"]');
  var badge = acc.querySelector('.pd-count');
  function update() {
    var n = Array.prototype.filter.call(boxes, function (b) { return b.checked; }).length;
    badge.textContent = n + ' / ' + boxes.length;
    acc.classList.toggle('done', n === boxes.length);
  }
  boxes.forEach(function (b) { b.addEventListener('change', update); });
  update();
});
</script>