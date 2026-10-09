---
layout: post
published: true
title: "Passkeys, frases y contraseñas: guía y checklist para vos y tu equipo"
description: "Cómo proteger las cuentas de tu negocio con passkeys, frases-contraseña y un gestor, explicado simple para dueños de negocios."
date: 2026-09-28 09:00
author: Isma Gonzalez
categories: security
tags: [passkeys, contraseñas, pymes, ciberseguridad]
duration:
banner_image: /assets/images/passkeys-frases-contrasenas-banner.jpg
banner_image_credits:
checklist:
- title: Passkeys primero
  items:
  - text: 'Activaste passkey en tu correo principal. Google, Microsoft y Apple ya las tienen: buscá "Passkeys" o "Llaves de acceso" en la configuración de seguridad de tu cuenta.'
    ref: NIST · UK NCSC
  - text: Revisaste si tu banco y las apps que usás para trabajar ofrecen passkey, y la activaste.
    ref: NIST · University of Colorado
  - text: Tu teléfono tiene un PIN de 6 dígitos o más y lo tapás al escribirlo en público. Si alguien lo ve y luego te roba el teléfono, puede entrar a todo. En iPhone, activá también la **Protección en caso de robo**.
    ref: Apple Support
  - text: Tenés al día tu correo y teléfono de recuperación. Si perdés el teléfono, recuperás tus passkeys en uno nuevo con tu cuenta de Apple, Google o tu gestor.
    ref: Apple · Google · FIDO Alliance
- title: 'Si no hay passkey: verificación en dos pasos'
  items:
  - text: Toda cuenta sin passkey tiene la verificación en dos pasos activada. Empezá por correo, banco y redes del negocio.
    ref: NIST · CISA · Morgan Stanley
  - text: Si podés elegir, preferís una **app de códigos** (Microsoft o Google Authenticator) en lugar de **códigos por SMS**. Los SMS sirven, pero alguien puede duplicar tu número de teléfono y recibirlos.
    ref: NIST · KnowBe4
  - text: Vos y tu equipo saben que **nadie de verdad te pide un código** por llamada, WhatsApp o correo. Ni el banco, ni "soporte técnico". Si te lo piden, es estafa.
    ref: KnowBe4
- title: Una app para guardar tus frases (gestor de contraseñas)
  items:
  - text: 'Usás un gestor de contraseñas. Opciones conocidas con plan para empresas: Bitwarden, 1Password y Proton Pass. Para uso personal también sirven Contraseñas de Apple o el de Google.'
    ref: NIST · University of Colorado · Morgan Stanley
  - text: Dejás que el gestor cree una frase distinta para cada cuenta. La mayoría puede generar frases de palabras en vez de letras sueltas. Además, solo llena tus datos en la página real, así que te protege de páginas falsas.
    ref: KnowBe4 · Morgan Stanley
  - text: 'La frase que abre el gestor es larga, única y solo vos la sabés, y además tiene passkey o verificación en dos pasos. En el mejor caso, solo memorizás dos: la del teléfono o computadora y la del gestor.'
    ref: KnowBe4 · NIST
  - text: Hacés caso cuando el gestor te avisa que una clave es débil, está repetida o apareció en un robo de datos.
    ref: University of Colorado · Morgan Stanley
- title: Frases en vez de contraseñas
  items:
  - text: Las frases que memorizás tienen **al menos 15 caracteres**. Lo que más protege es el largo, no los símbolos raros.
    ref: NIST
  - text: 'Usás 4 o 5 palabras que no tengan nada que ver entre sí, separadas por guion, punto o espacio. Mejor si las elige el gestor: a las personas nos cuesta escoger al azar.'
    ref: NIST · University of Colorado
  - text: Si la página te obliga a poner mayúscula, número o símbolo, los ponés en medio de la frase, no al final. Un `1!` al final es lo primero que prueban.
    ref: KnowBe4
  - text: No usás nombres de hijos, pareja o mascota, fechas, tu equipo de fútbol, el nombre de la empresa, refranes ni canciones.
    ref: KnowBe4 · Morgan Stanley
  - text: 'Para recordarla, imaginás una escena absurda con esas palabras: una tortuga en un cafetal leyendo un mapa bajo la lluvia.'
- title: Una frase distinta para cada cuenta
  items:
  - text: No repetís claves. Si una tienda en línea donde compraste es hackeada, los delincuentes prueban ese mismo correo y clave en tu Gmail, tu banco y tus redes. Si es la misma, entran.
    ref: NIST · KnowBe4
  - text: 'No usás variaciones como `Clave2024` y `Clave2025`: para un atacante son la misma.'
    ref: KnowBe4
  - text: 'Separás lo personal de lo laboral: tu clave de Netflix no se parece a la del correo del negocio.'
    ref: KnowBe4
  - text: Buscaste tu correo en [haveibeenpwned.com](https://haveibeenpwned.com) para ver si ya apareció en algún robo de datos.
    ref: NIST · KnowBe4
- title: Tus 3 cuentas más importantes
  items:
  - text: '**Tu correo principal:** es la llave maestra. Cada vez que hacés clic en "olvidé mi contraseña", el enlace llega ahí.'
    ref: KnowBe4
  - text: '**Banco, cobros y facturación:** banca en línea, plataformas de cobro, sistema de facturación y contabilidad.'
    ref: Morgan Stanley
  - text: '**Las cuentas que controlan el negocio:** la cuenta principal de Microsoft 365 o Google Workspace, donde tenés registrado el nombre de tu página web (quien la controla, controla tu correo) y la cuenta que administra tus redes sociales.'
  - text: Las tres tienen passkey. Si alguna no la ofrece, tiene una frase única creada por el gestor más verificación en dos pasos.
  - text: En las preguntas de seguridad ("¿nombre de tu primera mascota?") respondés algo falso y lo guardás en el gestor. La respuesta real se encuentra en tus redes sociales.
    ref: KnowBe4
- title: ¿Cada cuánto cambiarlas?
  items:
  - text: 'No cambiás claves solo porque pasaron 3 meses. Cambiarlas por calendario no protege: la gente termina pasando de `Verano2025!` a `Otoño2025!`. Si querés una rutina, una vez al año es suficiente, y con un gestor no te cuesta nada.'
    ref: NIST · University of Colorado · KnowBe4
  - text: 'Sí la cambiás **de inmediato** si: aparece en un robo de datos, se la dijiste a alguien, alguien que la conocía dejó el negocio, la usaste en una computadora pública o te llega un aviso de un inicio de sesión que no fuiste vos.'
    ref: NIST · Morgan Stanley
  - text: Cambiaste la clave que venía de fábrica en el router del internet, las cámaras, las impresoras y la máquina de cobro.
    ref: Morgan Stanley · KnowBe4
- title: Tu equipo
  items:
  - text: Todo el equipo usa el mismo gestor de contraseñas del negocio. Las claves que se comparten, se comparten desde ahí; nunca por WhatsApp, correo, Excel o papelitos pegados.
    ref: KnowBe4
  - text: Todos tienen passkey o verificación en dos pasos en el correo y los sistemas importantes, no solo vos.
    ref: KnowBe4 · CISA
  - text: Cada persona tiene su propio usuario. Nada de una sola cuenta compartida entre cinco.
    ref: KnowBe4
  - text: Cada quien solo tiene acceso a lo que necesita para su trabajo.
    ref: KnowBe4
  - text: Cuando alguien deja el negocio, ese mismo día le quitás los accesos y cambiás las claves compartidas que conocía.
    ref: KnowBe4
  - text: Una vez al año hacen una charla corta para aprender a reconocer correos y mensajes falsos.
    ref: KnowBe4
- title: Si te roban una clave
  items:
  - text: La cambiás de inmediato, en esa cuenta y en cualquier otra donde la hayás usado.
    ref: Morgan Stanley
  - text: En la configuración de la cuenta, cerrás la sesión en todos los dispositivos.
  - text: Revisás que tu correo no esté reenviando mensajes a una dirección que no conocés. Es un truco común para espiarte sin que lo notés.
  - text: Activás passkey o verificación en dos pasos si todavía no los tenía.
  - text: Si la cuenta tenía datos de clientes, revisás si tenés que avisarles (en Costa Rica, ver la [guía de protección de datos](/security/2026/09/26/checklist-proteccion-datos-cr.html)).
    ref: Ley 8968 · Reglamento arts. 38 y 39
---
{% include guide.html %}

Si vos o tu equipo usan correo, banca en línea, redes sociales o cualquier sistema del negocio (o sea, todos), esta guía es para vos.

## Lo básico en 1 minuto

Hay tres formas de entrar a tus cuentas. De mejor a peor:

1. **Passkey (llave de acceso): la mejor.** Entrás con tu huella, tu cara o el PIN del teléfono. No hay nada que escribir, recordar ni robar. Usala siempre que la cuenta la ofrezca.
2. **Frase-contraseña: la segunda mejor.** Varias palabras al azar juntas, como `tortuga-cafetal-mapa-lluvia`. Larga, difícil de adivinar y fácil de recordar. Para cuentas que todavía no tienen passkey.
3. **Contraseña corta tradicional: evitala.** Algo como `Empresa2025!`. Parece segura, pero se adivina rápido.

> **Verificación en dos pasos** es un segundo candado, como un código en una app del teléfono. Aunque alguien tenga tu frase, no le alcanza para entrar.
>
> **Gestor de contraseñas** es una app que funciona como caja fuerte. Crea y guarda una frase distinta para cada cuenta. Vos solo memorizás una: la que abre la caja fuerte.
{: .pd-box}

> **Ojo:** la forma más común de robar una clave es engañarte con un correo o mensaje falso para que la escribás en una página falsa. Ahí da igual qué tan larga sea. Las passkeys no se pueden entregar así, por eso son la mejor opción.
{: .pd-box .warn}

## ¿Por qué importa?

Quien entra con tu clave no "hackea" nada: usa tu llave. El sistema cree que sos vos y le abre la puerta. Lo que suele pasar después:

- **Fraude de facturas:** desde tu correo real le escriben a un cliente: "cambiamos de cuenta bancaria". La plata se va a otro lado.
- **Cuentas bancarias o de cobro vaciadas.**
- **Secuestro de información:** bloquean los archivos del negocio y piden rescate para devolverlos.
- **Redes del negocio robadas** y usadas para estafar a tus propios clientes.
- **Datos de clientes filtrados:** multas, reclamos y pérdida de confianza.

Más de 2 de cada 3 personas usan la misma contraseña en varias cuentas (Security.org). En 2024 hubo más de 3.000 filtraciones de datos solo en EE. UU. (Identity Theft Resource Center).
{: .pd-small}

## Checklist

Abrí cada sección y marcá lo que ya cumplís.

{% include checklist.html %}

## ¿Qué tan larga debe ser tu frase?

| Largo | Ejemplo | ¿Qué tan segura? |
|---|---|---|
| 8 caracteres | `Maria85!` | Débil. Si hackean el sitio donde la usás, la descubren en minutos u horas. |
| 12 caracteres | `Cafetal2025!` | Mejor, pero sigue siendo fácil de descubrir si hackean el sitio. |
| 15 o más | `perro-nube-sartén` | Mínimo recomendado. |
| 20 o más | `tortuga-cafetal-mapa-lluvia` | Fuerte. Muy difícil de descubrir, incluso si hackean el sitio. |
{: .pd-table .nw-2}

Ejemplos ilustrativos, no los usés.
{: .pd-small}

## Empieza hoy: 5 acciones rápidas

1. Buscá tu correo en [haveibeenpwned.com](https://haveibeenpwned.com) para ver si ya apareció en algún robo de datos.
2. Activá passkey en tu correo principal. Si no la tiene, activá la verificación en dos pasos.
3. Hacé lo mismo en tu banco.
4. Descargá una app para guardar tus claves (Bitwarden o 1Password, por ejemplo) y creá la única frase que vas a memorizar: la que abre esa app.
5. En tu correo, tu banco y las cuentas que controlan tu negocio: si no tienen passkey, pedile a la app que te cree una frase nueva y guardala ahí.

Después, cada vez que entrés a un sitio, activá passkey si la ofrece o cambiá la clave por una frase nueva del gestor. En un par de meses tenés todo cubierto sin sacrificar un fin de semana.

> **¿Dudas o querés revisar el caso de tu equipo?** Escribime por Instagram a [**@ismagonrod**](https://instagram.com/ismagonrod) y lo vemos juntos.
{: .pd-box}

**Fuentes:** [NIST: How Do I Create a Good Password?](https://www.nist.gov/cybersecurity-and-privacy/how-do-i-create-good-password) · [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) · [CISA: Use Strong Passwords](https://www.cisa.gov/secure-our-world/use-strong-passwords) · [Morgan Stanley: 10 Essential Password Security Tips](https://www.morganstanley.com/articles/password-security-guidelines-best-practices) · [University of Colorado](https://www.cu.edu/blog/tech-tips/best-practices-strong-password-security-and-management-0) · [UK NCSC](https://www.ncsc.gov.uk/news/ncsc-leave-passwords-in-the-past-passkeys-are-the-future) · [Apple Support](https://support.apple.com/en-us/120758) · KnowBe4, *What Your Password Policy Should Be*.
{: .pd-small}
