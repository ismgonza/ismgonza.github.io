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
banner_image: /assets/images/gmail-sin-sms-banner.jpg
banner_image_credits:
checklist:
- title: Creá tu llave de acceso
  items:
  - text: En **Seguridad y acceso**, entraste a **Llaves de acceso y llaves de seguridad** y tocaste **Crear una llave de acceso**. Confirmaste con tu huella, cara o PIN.
    ref: Google · FIDO Alliance
  - text: 'Si te apareció **"¿Aprobar esta llave de acceso?"**, es normal: Google pone una espera de seguridad a las llaves nuevas. Podés aprobarla con otra llave que ya tengas o esperar.'
    ref: Google
  - text: 'Sabés dónde quedó guardada: en **iPhone**, en la app **Contraseñas**; en **Android**, en el **Gestor de contraseñas de Google** (algunos Samsung ofrecen Samsung Pass). Si cambiás de celular, se recupera con esa misma cuenta.'
    ref: Apple · Google
- title: Activá la verificación en 2 pasos
  items:
  - text: 'En **Seguridad y acceso → Verificación en 2 pasos**, la activaste. Si está apagada, a alguien le basta tu contraseña para entrar: la llave de acceso es una puerta más segura, pero la puerta vieja sigue abierta.'
    ref: Google · NIST · CISA
  - text: Dejaste tu llave de acceso como segundo paso. Google la acepta así.
    ref: Google
- title: Agregá segundos pasos que no sean SMS
  items:
  - text: 'Activaste el **Mensaje de Google**: al iniciar sesión te llega un aviso en tu celular y tocás "Sí, soy yo". Leé siempre desde dónde es el intento antes de aprobar.'
    ref: Google
  - text: '**Opcional**, si querés un respaldo más: una **app autenticadora**, una app que te muestra un código de 6 dígitos que cambia cada 30 segundos (por ejemplo, Google Authenticator o Microsoft Authenticator). Si no la conocés, podés saltarte este punto.'
    ref: NIST · Google
- title: Guardá tus códigos de respaldo
  items:
  - text: En **Verificación en 2 pasos → Códigos de respaldo**, generaste tus códigos. Sirven una sola vez cada uno y te salvan si perdés el celular.
    ref: Google
  - text: Los guardaste en tu gestor de contraseñas o impresos en un lugar seguro. **No** en tu mismo correo ni en una foto del celular.
    ref: Google
- title: Desactivá el mensaje de texto (SMS)
  items:
  - text: '**Antes de quitarlo**, comprobaste que tenés al menos dos opciones de los pasos 1 a 4: llave de acceso, Mensaje de Google, códigos de respaldo o autenticadora. Este es el paso que evita que te quedes sin acceso.'
  - text: En **Verificación en 2 pasos**, buscaste la sección de **números de teléfono** y eliminaste tu número como segundo paso.
    ref: Google · NIST SP 800-63B
  - text: Cerraste sesión y probaste entrar de nuevo para confirmar que ya no te ofrece el SMS.
- title: Revisá tus datos de recuperación
  items:
  - text: Tu **correo de recuperación** está al día y es una cuenta que también tiene llave de acceso o verificación en 2 pasos. Si ese correo es débil, se vuelve la puerta trasera.
    ref: Google
  - text: Sabés que el **teléfono de recuperación** también recibe SMS. Si lo dejás, le preguntaste a tu operadora si ofrece algún **PIN o bloqueo para los cambios de chip** de tu línea (no todas lo ofrecen).
    ref: FTC
- title: Si pasa algo raro
  items:
  - text: 'Sabés la señal clásica: tu celular marca **"Sin servicio"** de la nada, en un lugar donde siempre tenés señal. Llamás a tu operadora de inmediato desde otro teléfono.'
    ref: FTC
  - text: 'Si perdés el celular: entrás con un código de respaldo, revisás **Tus dispositivos** en Seguridad y acceso y cerrás la sesión del celular perdido.'
    ref: Google
  - text: 'Si te llega un aviso de inicio de sesión que no fuiste vos: cambiás la contraseña y revisás que tu correo no esté reenviando mensajes a otra dirección.'
---
{% include guide.html %}

> **¿Venís del reel? Antes de desactivar el mensaje de texto, tené al menos 2 de estas 3:**
>
> 🔑 Una **llave de acceso** (passkey)<br>📱 El **Mensaje de Google** en tu celular<br>🧾 Tus **códigos de respaldo**, guardados fuera del correo
>
> Con eso listo, ya podés quitar tu número. Si lo quitás antes, te podés quedar sin acceso a tu propia cuenta. Abajo está cada paso 👇
{: #reel .pd-box .warn}

Esta guía cubre lo que no cabía en el reel: **cómo sacar el mensaje de texto de la ecuación** para que el cambio de chip no le sirva a nadie.

## Lo básico en 1 minuto

En el **SIM swap**, alguien convence a tu operadora de pasar tu número a otro chip. Desde ese momento, los mensajes de texto le llegan a él. Si tu Gmail se protege con un código por SMS, ese código también.

Formas de confirmar que sos vos, de mejor a peor:

| Método | Cambio de chip | Página falsa |
|---|---|---|
| **Llave de acceso (passkey)** | ✅ No le sirve | ✅ No le sirve |
| **Mensaje de Google** en tu celular | ✅ No le sirve | ⚠️ Podés aprobar sin darte cuenta |
| **App autenticadora** (código de 6 dígitos) | ✅ No le sirve | ⚠️ Podés escribir el código en la página falsa |
| **Código por SMS** | ❌ Le llega a él | ❌ Le sirve |
{: .pd-table .nw-2}

> **Ojo:** crear la llave de acceso no alcanza si el SMS sigue activo. Al iniciar sesión, el atacante toca **"Probar otro método"**, elige el mensaje de texto y listo. Por eso el último paso es quitarlo.
{: .pd-box .warn}

## Checklist

Hacelo en este orden. Primero agregás opciones seguras, al final quitás el mensaje de texto. Así nunca te quedás afuera de tu propia cuenta.

Ruta base en el celular: Gmail → tu foto de perfil → **Administrar tu Cuenta de Google** → **Seguridad y acceso**. Los nombres de los menús pueden cambiar un poco según tu versión.
{: .pd-small}

{% include checklist.html %}

## Empezá hoy: 4 acciones rápidas

1. Creá tu llave de acceso (como en el reel).
2. Activá la verificación en 2 pasos y el Mensaje de Google.
3. Generá y guardá tus códigos de respaldo.
4. Desactivá el mensaje de texto: quitá tu número de teléfono como segundo paso (siempre al final).

Son unos 10 minutos. Después, un cambio de chip ya no te deja sin correo.

> **¿Querés el nivel máximo?** Si manejás dinero, datos de clientes o sos figura pública, mirá el [Programa de Protección Avanzada de Google](https://landing.google.com/advancedprotection/): exige llave de acceso o llave física para todo.
>
> Y si querés ordenar el resto de tus claves (frases, gestor, equipo), está la [guía completa de passkeys y contraseñas](/security/2026/09/26/passkeys-frases-contrasenas.html).
{: .pd-box}

> **¿Te trabaste en algún paso?** Escribime por Instagram a [**@ismagonrod**](https://instagram.com/ismagonrod) y lo vemos.
{: .pd-box}

**Fuentes:** [Google: Activar la verificación en 2 pasos](https://support.google.com/accounts/answer/185839) · [Google: Códigos de respaldo](https://support.google.com/accounts/answer/1187538) · [Google: Llaves de acceso](https://g.co/passkeys) · [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) · [CISA: Turn On MFA](https://www.cisa.gov/secure-our-world/turn-mfa) · [FTC: SIM swap scams](https://consumer.ftc.gov/articles/sim-swap-scams-how-protect-yourself) · [FIDO Alliance: Passkeys](https://fidoalliance.org/passkeys/).
{: .pd-small}
