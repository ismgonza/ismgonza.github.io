---
layout: post
published: true
title: "Protección de datos personales en Costa Rica: guía y checklist para negocios"
description: "Lo que dice la Ley 8968, su reglamento y la directriz de cobros 2026, explicado simple para dueños de negocios."
date: 2026-09-26 08:00
author: Isma Gonzalez
categories: security
tags: [protección de datos, Costa Rica, PRODHAB, pymes, ciberseguridad]
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
.pd-guide .pd-table th:nth-child(3),.pd-guide .pd-table td:nth-child(3){min-width:11rem;white-space:nowrap}
.pd-table td{padding:8px 10px;border:1px solid var(--line);vertical-align:top}
.pd-table tr:nth-child(even) td{background:var(--light)}
.pd-scroll{overflow-x:auto}
.pd-small{font-size:.82em;color:var(--grey)}
@media (prefers-reduced-motion:reduce){.pd-acc summary::after{transition:none}}
</style>

<div class="pd-guide" markdown="1">

Si tu negocio guarda nombres, teléfonos, correos, cédulas o historiales de clientes (clínicas, agencias, consultorios, tiendas, gimnasios), esta guía es para vos.

## Lo básico en 1 minuto

En Costa Rica rigen tres normas principales:

- **Ley 8968**: Ley de Protección de la Persona frente al Tratamiento de sus Datos Personales (2011).
- **Reglamento**: Decreto Ejecutivo 37554-JP, con reformas de 2016 y 2019.
- **Directriz PRODHAB-DIR-DN-001-2026** (17 de julio de 2026): reglas nuevas para cobros.

La entidad que vigila su cumplimiento es la **PRODHAB** (Agencia de Protección de Datos de los Habitantes).

<div class="pd-box">
<p><strong>Dato personal</strong> es cualquier dato de una persona identificada o identificable: nombre, cédula, teléfono, correo, dirección, foto, historial de compras.</p>
<p><strong>Dato sensible</strong> es información íntima: salud, origen racial, religión, opiniones políticas, orientación sexual, condición socioeconómica, información biomédica o genética. Tiene reglas mucho más estrictas.</p>
</div>

## ¿Me aplica la ley?

El texto dice que no se aplica a bases de datos de uso **exclusivamente interno**, siempre que no se vendan ni comercialicen (Ley 8968 art. 2; Reglamento art. 3).

<div class="pd-box warn">
<p><strong>Ojo:</strong> esa excepción es fácil de perder. Si compartís datos con otra empresa, los usás en campañas con terceros, los vendés o trabajás con agencias de cobro, ya no es “solo interno”. Además, la directriz de 2026 se dirige a todo aquel que trate datos personales.</p>
<p><strong>Recomendación: trabajá como si la ley te aplicara.</strong> Cumplir es barato; una denuncia no.</p>
</div>

## Checklist

Abrí cada sección y marcá lo que ya cumplís.

</div>

<div class="pd-guide">
<details class="pd-acc"><summary><span class="pd-title">1. Antes de pedir datos: informá</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Tu formulario (papel, web o WhatsApp) explica de forma clara: que existe una base de datos, para qué usarás los datos, quién los verá, si responder es obligatorio, qué pasa si no los dan, qué derechos tienen, y el nombre y dirección de tu negocio.<span class="pd-ref">Ley 8968, art. 5.1</span></span></label></li>
<li><label><input type="checkbox"><span>Pedís solo los datos que realmente necesitás.<span class="pd-ref">Ley 8968, art. 6.4</span></span></label></li>
<li><label><input type="checkbox"><span>No usás los datos para otro fin distinto al que informaste (por ejemplo, datos de una cita usados después para marketing sin permiso). Es falta grave.<span class="pd-ref">Ley 8968, arts. 6.4 y 30.c</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">2. Consentimiento: por escrito y con prueba</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Obtenés el consentimiento <strong>por escrito</strong>, en papel o digital (casilla sin pre-marcar, firma digital, formulario web). Es fácil de entender y gratuito.<span class="pd-ref">Ley 8968, art. 5.2 · Reglamento art. 5</span></span></label></li>
<li><label><input type="checkbox"><span>Si el consentimiento va dentro de un contrato, tiene una <strong>cláusula específica e independiente</strong> sobre datos personales.<span class="pd-ref">Reglamento art. 2.f</span></span></label></li>
<li><label><input type="checkbox"><span>Guardás la prueba de cada consentimiento. Si hay un reclamo, a vos te toca demostrarlo.<span class="pd-ref">Reglamento art. 6</span></span></label></li>
<li><label><input type="checkbox"><span>Hay un medio fácil y gratuito para que el cliente retire su consentimiento.<span class="pd-ref">Reglamento art. 7</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">3. Datos sensibles (clave para clínicas)</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Sabés que tratar datos sensibles está <strong>prohibido</strong> salvo excepciones, y que nadie está obligado a darlos.<span class="pd-ref">Ley 8968, art. 9.1</span></span></label></li>
<li><label><input type="checkbox"><span>Si sos clínica o consultorio: los datos de salud solo los maneja personal de salud o personas con <strong>secreto profesional</strong>, y solo para prevención, diagnóstico, tratamiento o gestión del servicio.<span class="pd-ref">Ley 8968, art. 9.1.d</span></span></label></li>
<li><label><input type="checkbox"><span>Si no sos del área de salud, no pedís datos sensibles que no necesitás. Manejarlos sin base legal es <strong>falta gravísima</strong>.<span class="pd-ref">Ley 8968, art. 31.a</span></span></label></li>
<li><label><input type="checkbox"><span>Revisás la seguridad de los datos sensibles al menos una vez al año.<span class="pd-ref">Reglamento art. 37</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">4. Derechos de tus clientes: respondé a tiempo</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Tenés un canal simple (correo o formulario) para pedir acceso, corrección o eliminación de datos.<span class="pd-ref">Reglamento art. 16</span></span></label></li>
<li><label><input type="checkbox"><span>Respondés gratis en <strong>máximo 5 días hábiles</strong>.<span class="pd-ref">Ley 8968, art. 7 · Reglamento art. 18</span></span></label></li>
<li><label><input type="checkbox"><span>Si alguien retira su consentimiento: lo aplicás en 5 días hábiles, avisás en ese plazo a quienes les pasaste los datos, y si te piden confirmación, la das en 3 días hábiles.<span class="pd-ref">Reglamento arts. 8 y 9</span></span></label></li>
<li><label><input type="checkbox"><span>La respuesta cubre todo lo que tenés de esa persona, es clara y nunca revela datos de otras personas.<span class="pd-ref">Reglamento art. 20</span></span></label></li>
<li><label><input type="checkbox"><span>Si negás una solicitud, lo justificás por escrito. Negarse sin justificación es falta grave.<span class="pd-ref">Reglamento art. 22 · Ley 8968, art. 30.d-e</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">5. Seguridad: protegé lo que guardás</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Tenés medidas <strong>físicas</strong> (archivos con llave), <strong>lógicas</strong> (contraseñas fuertes, autenticación de múltiples factores (MFA), respaldos, accesos por rol) y <strong>administrativas</strong> (políticas y responsables).<span class="pd-ref">Ley 8968, art. 10 · Reglamento art. 34</span></span></label></li>
<li><label><input type="checkbox"><span>Tenés por escrito qué datos guardás, en qué sistemas, qué riesgos hay y un plan para cubrir lo que falta.<span class="pd-ref">Reglamento art. 36</span></span></label></li>
<li><label><input type="checkbox"><span>Tu personal sabe que debe guardar confidencialidad, incluso después de dejar el trabajo.<span class="pd-ref">Ley 8968, art. 11</span></span></label></li>
<li><label><input type="checkbox"><span>No enviás datos por medios inseguros (listas de clientes por chats personales o correos sin control).<span class="pd-ref">Ley 8968, art. 29.b</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">6. Proveedores y compartir datos</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Sabés que usar un proveedor (CRM, software de citas, nube, contador) <strong>no</strong> es transferencia, pero <strong>seguís siendo responsable</strong>: verificá que tenga seguridad adecuada.<span class="pd-ref">Reglamento arts. 29 y 40</span></span></label></li>
<li><label><input type="checkbox"><span>Tus proveedores solo usan los datos según tus instrucciones y por contrato.<span class="pd-ref">Reglamento arts. 30 y 31</span></span></label></li>
<li><label><input type="checkbox"><span>Si compartís datos con otra empresa para sus propios fines, tenés consentimiento expreso del cliente y un contrato con esa empresa.<span class="pd-ref">Ley 8968, art. 14 · Reglamento arts. 40 y 43</span></span></label></li>
<li><label><input type="checkbox"><span>Nunca enviás datos a bases de otras empresas en el extranjero sin consentimiento: es <strong>falta gravísima</strong>.<span class="pd-ref">Ley 8968, art. 31.f</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">7. Si te hackean o perdés datos</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Tenés un plan simple: quién decide, a quién se avisa y cómo.</span></label></li>
<li><label><input type="checkbox"><span>Avisás a los clientes afectados y a la PRODHAB en <strong>máximo 5 días hábiles</strong>.<span class="pd-ref">Reglamento arts. 38 y 39</span></span></label></li>
<li><label><input type="checkbox"><span>El aviso incluye: qué pasó, qué datos se comprometieron, qué hiciste de inmediato y dónde obtener más información.<span class="pd-ref">Reglamento art. 39</span></span></label></li>
<li><label><input type="checkbox"><span>En esos mismos 5 días iniciás una revisión para medir el daño y corregir.<span class="pd-ref">Reglamento art. 38</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">8. ¿Cuánto tiempo guardar los datos?</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Eliminás los datos que ya no necesitás para el fin por el que los pediste.<span class="pd-ref">Ley 8968, art. 6.1</span></span></label></li>
<li><label><input type="checkbox"><span>No conservás datos que puedan afectar a la persona por más de <strong>10 años</strong>, salvo que otra ley diga otra cosa. Si necesitás guardarlos más, los desasociás (que ya no se pueda identificar a la persona).<span class="pd-ref">Ley 8968, art. 6.1 · Reglamento art. 11</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">9. Cobros: reglas nuevas (julio 2026)</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Para cobrar solo pedís datos del <strong>titular</strong> de la deuda. Si pedís datos de terceros (referencias, familiares), necesitás el consentimiento expreso de esas personas.<span class="pd-ref">Directriz, punto I</span></span></label></li>
<li><label><input type="checkbox"><span>Nunca enviás mensajes de cobro a familiares, amigos o compañeros de trabajo que no tienen relación con la deuda ni lo autorizaron.<span class="pd-ref">Directriz, punto II</span></span></label></li>
<li><label><input type="checkbox"><span>No usás datos de contacto <strong>laboral</strong> para cobrar, salvo orden judicial firme.<span class="pd-ref">Directriz, punto III</span></span></label></li>
<li><label><input type="checkbox"><span>En todo mensaje de cobro queda claro quién es tu negocio.<span class="pd-ref">Directriz, punto IV</span></span></label></li>
<li><label><input type="checkbox"><span>Si contratás una agencia de cobro, verificás que cumpla estas reglas.<span class="pd-ref">Directriz: aplica a quien realice o contrate cobros</span></span></label></li>
</ul></details>
<details class="pd-acc"><summary><span class="pd-title">10. Inscripción ante la PRODHAB</span><span class="pd-count"></span></summary>
<ul class="pd-list">
<li><label><input type="checkbox"><span>Solo inscribís tu base de datos si la usás para <strong>distribuir, difundir o comercializar</strong> datos. Las bases internas no se inscriben.<span class="pd-ref">Ley 8968, art. 21 · Reglamento art. 44</span></span></label></li>
<li><label><input type="checkbox"><span>Si te toca inscribirte: canon anual de <strong>USD 200</strong>, del 1 al 31 de enero. No inscribirte cuando corresponde es falta gravísima.<span class="pd-ref">Ley 8968, arts. 31.e y 33 · Reglamento arts. 78 y 79</span></span></label></li>
</ul></details>
</div>

<div class="pd-guide" markdown="1">

## ¿Qué pasa si no cumplo?

<div class="pd-scroll">
<table class="pd-table">
<thead><tr><th>Falta</th><th>Multa (salarios base)</th><th>Aprox. 2026*</th><th>Ejemplos</th></tr></thead>
<tbody>
<tr><td>Leve</td><td>Hasta 5</td><td>Hasta ₡2,3 M</td><td>No informar al pedir datos; usar medios inseguros</td></tr>
<tr><td>Grave</td><td>5 a 20</td><td>₡2,3 M – ₡9,2 M</td><td>Sin consentimiento; usar datos para otro fin; no atender derechos</td></tr>
<tr><td>Gravísima</td><td>15 a 30 + suspensión de la base de datos de 1 a 6 meses</td><td>₡6,9 M – ₡13,9 M</td><td>Datos sensibles sin base legal; engaño; enviar datos al extranjero sin consentimiento; no inscribirse</td></tr>
</tbody>
</table>
</div>

<p class="pd-small">Ley 8968, arts. 28 a 31. *Aproximado con salario base 2026 de ₡462.200. La reincidencia en prácticas de cobro ya declaradas indebidas es agravante (Directriz, punto VII).</p>

## Empieza hoy: 5 acciones rápidas

1. Hacé una lista de dónde guardás datos de clientes: Excel, CRM, WhatsApp, correo, papel.
2. Agregá el aviso de privacidad y el check de consentimiento a tus formularios.
3. Creá un correo o canal para solicitudes de datos y respondé en menos de 5 días hábiles.
4. Activá la autenticación de múltiples factores (MFA), respaldos y accesos por rol; revisá qué pueden ver tus empleados.
5. Si cobrás deudas, dejá de contactar referencias o teléfonos de trabajo sin autorización.

<div class="pd-box">
<p><strong>¿Dudas o querés revisar tu caso?</strong> Escribime por Instagram a <a href="https://instagram.com/ismagonrod"><strong>@ismagonrod</strong></a> y lo vemos juntos. Para temas legales específicos, consultá también con un abogado especialista en protección de datos.</p>
</div>

<p class="pd-small"><strong>Fuentes oficiales:</strong> <a href="https://sinalevi.go.cr/ResultadosNormativa/Informacion?param1=70975&amp;param2=85989&amp;param3=1&amp;param4=">Ley 8968</a> · <a href="https://sinalevi.go.cr/ResultadosNormativa/Informacion?param1=74352&amp;param2=115361&amp;param3=1">Reglamento, Decreto Ejecutivo 37554-JP</a> · <a href="https://www.prodhab.go.cr/ver/acercade/normativa/PRODHAB-DIR-DN-001-2026.pdf">Directriz PRODHAB-DIR-DN-001-2026</a> (17 de julio de 2026).</p>

<p class="pd-small"><em>Esta guía es informativa y simplificada. No sustituye asesoría legal.</em></p>

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