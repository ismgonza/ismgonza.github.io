---
layout: post
published: true
title: "Passkeys, frases y contraseñas: guía y checklist para vos y tu equipo"
description: "Cómo proteger las cuentas de tu negocio con passkeys, frases-contraseña y un gestor, explicado simple para dueños de negocios."
date: 2026-09-26 09:00
author: Isma Gonzalez
categories: security
tags: [passkeys, contraseñas, pymes, ciberseguridad]
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

Si vos o tu equipo usan correo, banca en línea, redes sociales o cualquier sistema del negocio (o sea, todos), esta guía es para vos.

## Lo básico en 1 minuto

Hay tres formas de entrar a tus cuentas. De mejor a peor:

1. **Passkey (llave de acceso): la mejor.** Entrás con tu huella, tu cara o el PIN del teléfono. No hay nada que escribir, recordar ni robar. Usala siempre que la cuenta la ofrezca.
2. **Frase-contraseña: la segunda mejor.** Varias palabras al azar juntas, como `tortuga-cafetal-mapa-lluvia`. Larga, difícil de adivinar y fácil de recordar. Para cuentas que todavía no tienen passkey.
3. **Contraseña corta tradicional: evitala.** Algo como `Empresa2025!`. Parece segura, pero se adivina rápido.

<div class="pd-box">
<p><strong>Verificación en dos pasos</strong> es un segundo candado, como un código en una app del teléfono. Aunque alguien tenga tu frase, no le alcanza para entrar.</p>
<p><strong>Gestor de contraseñas</strong> es una app que funciona como caja fuerte. Crea y guarda una frase distinta para cada cuenta. Vos solo memorizás una: la que abre la caja fuerte.</p>
</div>

<div class="pd-box warn">
<p><strong>Ojo:</strong> la forma más común de robar una clave es engañarte con un correo o mensaje falso para que la escribás en una página falsa. Ahí da igual qué tan larga sea. Las passkeys no se pueden entregar así, por eso son la mejor opción.</p>
</div>

## ¿Por qué importa?

Quien entra con tu clave no "hackea" nada: usa tu llave. El sistema cree que sos vos y le abre la puerta. Lo que suele pasar después:

- **Fraude de facturas:** desde tu correo real le escriben a un cliente: "cambiamos de cuenta bancaria". La plata se va a otro lado.
- **Cuentas bancarias o de cobro vaciadas.**
- **Secuestro de información:** bloquean los archivos del negocio y piden rescate para devolverlos.
- **Redes del negocio robadas** y usadas para estafar a tus propios clientes.
- **Datos de clientes filtrados:** multas, reclamos y pérdida de confianza.

<p class="pd-small">Más de 2 de cada 3 personas usan la misma contraseña en varias cuentas (Security.org, citado por Morgan Stanley). En 2024 hubo más de 3.000 filtraciones de datos solo en EE. UU. (Identity Theft Resource Center, citado por NIST).</p>

## Checklist

Abrí cada sección y marcá lo que ya cumplís.

</div>

<div class="pd-guide">
<details class="pd-acc"><summary><span class="pd-title">1. Passkeys primero</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Activaste passkey en tu correo principal. Google, Microsoft y Apple ya las tienen: buscá "Passkeys" o "Llaves de acceso" en la configuración de seguridad de tu cuenta.<span class="pd-ref">NIST · UK NCSC</span></span></label></li>
<li><label><input type="checkbox"><span>Revisaste si tu banco y las apps que usás para trabajar ofrecen passkey, y la activaste.<span class="pd-ref">NIST · University of Colorado</span></span></label></li>
<li><label><input type="checkbox"><span>Tu teléfono tiene un PIN de 6 dígitos o más y lo tapás al escribirlo en público. Si alguien lo ve y luego te roba el teléfono, puede entrar a todo. En iPhone, activá también la <strong>Protección en caso de robo</strong>.<span class="pd-ref">Apple Support</span></span></label></li>
<li><label><input type="checkbox"><span>Tenés al día tu correo y teléfono de recuperación. Si perdés el teléfono, recuperás tus passkeys en uno nuevo con tu cuenta de Apple, Google o tu gestor.<span class="pd-ref">Apple · Google · FIDO Alliance</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">2. Si no hay passkey: verificación en dos pasos</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Toda cuenta sin passkey tiene la verificación en dos pasos activada. Empezá por correo, banco y redes del negocio.<span class="pd-ref">NIST · CISA · Morgan Stanley</span></span></label></li>
<li><label><input type="checkbox"><span>Si podés elegir, preferís una <strong>app de códigos</strong> (Microsoft o Google Authenticator) en lugar de <strong>códigos por SMS</strong>. Los SMS sirven, pero alguien puede duplicar tu número de teléfono y recibirlos.<span class="pd-ref">NIST · KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>Vos y tu equipo saben que <strong>nadie de verdad te pide un código</strong> por llamada, WhatsApp o correo. Ni el banco, ni "soporte técnico". Si te lo piden, es estafa.<span class="pd-ref">KnowBe4</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">3. Una app para guardar tus frases (gestor de contraseñas)</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Usás un gestor de contraseñas. Opciones conocidas con plan para empresas: Bitwarden, 1Password y Proton Pass. Para uso personal también sirven Contraseñas de Apple o el de Google.<span class="pd-ref">NIST · University of Colorado · Morgan Stanley</span></span></label></li>
<li><label><input type="checkbox"><span>Dejás que el gestor cree una frase distinta para cada cuenta. La mayoría puede generar frases de palabras en vez de letras sueltas. Además, solo llena tus datos en la página real, así que te protege de páginas falsas.<span class="pd-ref">KnowBe4 · Morgan Stanley</span></span></label></li>
<li><label><input type="checkbox"><span>La frase que abre el gestor es larga, única y solo vos la sabés, y además tiene passkey o verificación en dos pasos. En el mejor caso, solo memorizás dos: la del teléfono o computadora y la del gestor.<span class="pd-ref">KnowBe4 · NIST</span></span></label></li>
<li><label><input type="checkbox"><span>Hacés caso cuando el gestor te avisa que una clave es débil, está repetida o apareció en un robo de datos.<span class="pd-ref">University of Colorado · Morgan Stanley</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">4. Frases en vez de contraseñas</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Las frases que memorizás tienen <strong>al menos 15 caracteres</strong>. Lo que más protege es el largo, no los símbolos raros.<span class="pd-ref">NIST</span></span></label></li>
<li><label><input type="checkbox"><span>Usás 4 o 5 palabras que no tengan nada que ver entre sí, separadas por guion, punto o espacio. Mejor si las elige el gestor: a las personas nos cuesta escoger al azar.<span class="pd-ref">NIST · University of Colorado</span></span></label></li>
<li><label><input type="checkbox"><span>Si la página te obliga a poner mayúscula, número o símbolo, los ponés en medio de la frase, no al final. Un <code>1!</code> al final es lo primero que prueban.<span class="pd-ref">KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>No usás nombres de hijos, pareja o mascota, fechas, tu equipo de fútbol, el nombre de la empresa, refranes ni canciones.<span class="pd-ref">KnowBe4 · Morgan Stanley</span></span></label></li>
<li><label><input type="checkbox"><span>Para recordarla, imaginás una escena absurda con esas palabras: una tortuga en un cafetal leyendo un mapa bajo la lluvia.</span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">5. Una frase distinta para cada cuenta</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>No repetís claves. Si una tienda en línea donde compraste es hackeada, los delincuentes prueban ese mismo correo y clave en tu Gmail, tu banco y tus redes. Si es la misma, entran.<span class="pd-ref">NIST · KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>No usás variaciones como <code>Clave2024</code> y <code>Clave2025</code>: para un atacante son la misma.<span class="pd-ref">KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>Separás lo personal de lo laboral: tu clave de Netflix no se parece a la del correo del negocio.<span class="pd-ref">KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>Buscaste tu correo en <a href="https://haveibeenpwned.com">haveibeenpwned.com</a> para ver si ya apareció en algún robo de datos.<span class="pd-ref">NIST · KnowBe4</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">6. Tus 3 cuentas más importantes</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span><strong>Tu correo principal:</strong> es la llave maestra. Cada vez que hacés clic en "olvidé mi contraseña", el enlace llega ahí.<span class="pd-ref">KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span><strong>Banco, cobros y facturación:</strong> banca en línea, plataformas de cobro, sistema de facturación y contabilidad.<span class="pd-ref">Morgan Stanley</span></span></label></li>
<li><label><input type="checkbox"><span><strong>Las cuentas que controlan el negocio:</strong> la cuenta principal de Microsoft 365 o Google Workspace, donde tenés registrado el nombre de tu página web (quien la controla, controla tu correo) y la cuenta que administra tus redes sociales.</span></label></li>
<li><label><input type="checkbox"><span>Las tres tienen passkey. Si alguna no la ofrece, tiene una frase única creada por el gestor más verificación en dos pasos.</span></label></li>
<li><label><input type="checkbox"><span>En las preguntas de seguridad ("¿nombre de tu primera mascota?") respondés algo falso y lo guardás en el gestor. La respuesta real se encuentra en tus redes sociales.<span class="pd-ref">KnowBe4</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">7. ¿Cada cuánto cambiarlas?</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>No cambiás claves solo porque pasaron 3 meses. NIST ya no lo recomienda: la gente termina pasando de <code>Verano2025!</code> a <code>Otoño2025!</code>, y eso no protege nada. (KnowBe4 sugiere una vez al año; con un gestor no te cuesta nada.)<span class="pd-ref">NIST · University of Colorado · KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>Sí la cambiás <strong>de inmediato</strong> si: aparece en un robo de datos, se la dijiste a alguien, alguien que la conocía dejó el negocio, la usaste en una computadora pública o te llega un aviso de un inicio de sesión que no fuiste vos.<span class="pd-ref">NIST · Morgan Stanley</span></span></label></li>
<li><label><input type="checkbox"><span>Cambiaste la clave que venía de fábrica en el router del internet, las cámaras, las impresoras y la máquina de cobro.<span class="pd-ref">Morgan Stanley · KnowBe4</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">8. Tu equipo</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Todo el equipo usa el mismo gestor de contraseñas del negocio. Las claves que se comparten, se comparten desde ahí; nunca por WhatsApp, correo, Excel o papelitos pegados.<span class="pd-ref">KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>Todos tienen passkey o verificación en dos pasos en el correo y los sistemas importantes, no solo vos.<span class="pd-ref">KnowBe4 · CISA</span></span></label></li>
<li><label><input type="checkbox"><span>Cada persona tiene su propio usuario. Nada de una sola cuenta compartida entre cinco.<span class="pd-ref">KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>Cada quien solo tiene acceso a lo que necesita para su trabajo.<span class="pd-ref">KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>Cuando alguien deja el negocio, ese mismo día le quitás los accesos y cambiás las claves compartidas que conocía.<span class="pd-ref">KnowBe4</span></span></label></li>
<li><label><input type="checkbox"><span>Una vez al año hacen una charla corta para aprender a reconocer correos y mensajes falsos.<span class="pd-ref">KnowBe4</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">9. Si te roban una clave</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>La cambiás de inmediato, en esa cuenta y en cualquier otra donde la hayás usado.<span class="pd-ref">Morgan Stanley</span></span></label></li>
<li><label><input type="checkbox"><span>En la configuración de la cuenta, cerrás la sesión en todos los dispositivos.</span></label></li>
<li><label><input type="checkbox"><span>Revisás que tu correo no esté reenviando mensajes a una dirección que no conocés. Es un truco común para espiarte sin que lo notés.</span></label></li>
<li><label><input type="checkbox"><span>Activás passkey o verificación en dos pasos si todavía no los tenía.</span></label></li>
<li><label><input type="checkbox"><span>Si la cuenta tenía datos de clientes, revisás si tenés que avisarles (en Costa Rica, ver la <a href="/security/2026/09/26/checklist-proteccion-datos-cr.html">guía de protección de datos</a>).<span class="pd-ref">Ley 8968 · Reglamento arts. 38 y 39</span></span></label></li>
</ul></details>
</div>

<div class="pd-guide" markdown="1">

## ¿Qué tan larga debe ser tu frase?

<div class="pd-scroll">
<table class="pd-table">
<thead><tr><th>Largo</th><th>Ejemplo</th><th>¿Qué tan segura?</th></tr></thead>
<tbody>
<tr><td>8 caracteres</td><td><code>Maria85!</code></td><td>Débil. Si hackean el sitio donde la usás, la descubren en minutos u horas.</td></tr>
<tr><td>12 caracteres</td><td><code>Cafetal2025!</code></td><td>Mejor, pero sigue siendo fácil de descubrir si hackean el sitio.</td></tr>
<tr><td>15 o más</td><td><code>perro-nube-sartén</code></td><td>El mínimo que recomienda NIST.</td></tr>
<tr><td>20 o más</td><td><code>tortuga-cafetal-mapa-lluvia</code></td><td>Fuerte. Muy difícil de descubrir, incluso si hackean el sitio.</td></tr>
</tbody>
</table>
</div>

<p class="pd-small">Ejemplos ilustrativos, no los usés. Basado en NIST y KnowBe4, <em>What Your Password Policy Should Be</em>.</p>

## Empieza hoy: 5 acciones rápidas

1. Buscá tu correo en [haveibeenpwned.com](https://haveibeenpwned.com) para ver si ya apareció en algún robo de datos.
2. Activá passkey en tu correo principal. Si no la tiene, activá la verificación en dos pasos.
3. Hacé lo mismo en tu banco.
4. Descargá una app para guardar tus claves (Bitwarden o 1Password, por ejemplo) y creá la única frase que vas a memorizar: la que abre esa app.
5. En tu correo, tu banco y las cuentas que controlan tu negocio: si no tienen passkey, pedile a la app que te cree una frase nueva y guardala ahí.

Después, cada vez que entrés a un sitio, activá passkey si la ofrece o cambiá la clave por una frase nueva del gestor. En un par de meses tenés todo cubierto sin sacrificar un fin de semana.

<div class="pd-box">
<p><strong>¿Dudas o querés revisar el caso de tu equipo?</strong> Escribime por Instagram a <a href="https://instagram.com/ismagonrod"><strong>@ismagonrod</strong></a> y lo vemos juntos.</p>
</div>

<p class="pd-small"><strong>Fuentes:</strong> <a href="https://www.nist.gov/cybersecurity-and-privacy/how-do-i-create-good-password">NIST: How Do I Create a Good Password?</a> · <a href="https://pages.nist.gov/800-63-4/sp800-63b.html">NIST SP 800-63B</a> · <a href="https://www.cisa.gov/secure-our-world/use-strong-passwords">CISA: Use Strong Passwords</a> · <a href="https://www.morganstanley.com/articles/password-security-guidelines-best-practices">Morgan Stanley: 10 Essential Password Security Tips</a> · <a href="https://www.cu.edu/blog/tech-tips/best-practices-strong-password-security-and-management-0">University of Colorado</a> · <a href="https://www.ncsc.gov.uk/news/ncsc-leave-passwords-in-the-past-passkeys-are-the-future">UK NCSC</a> · <a href="https://support.apple.com/en-us/120758">Apple Support</a> · KnowBe4, <em>What Your Password Policy Should Be</em>.</p>

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