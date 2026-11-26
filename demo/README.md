# Demo de RBAC / ITGC

Laboratorio estático para explicar el hito de recepción de solicitudes. No consume la API .NET, no usa credenciales ni ejecuta aprovisionamiento. Los ejemplos son ficticios y el estado se conserva únicamente en memoria de la pestaña; al recargar o reiniciar se pierde.

## Probar localmente

Requiere Node.js 22+ para pruebas/build y Python 3 para el servidor. Sin dependencias npm externas.

```sh
cd demo
npm test
npm run build
python -m http.server 8096 --bind 127.0.0.1 --directory dist
```

Abrir http://localhost:8096. Usar localhost o HTTPS: Web Crypto requiere un contexto seguro. No abrir `index.html` por `file://`, porque la demo usa módulos JavaScript.

## Recorrido de dos minutos

1. Enviar **Acceso válido**: queda `Pending`, con respuesta simulada 202 y un evento nuevo.
2. Elegir **Conflicto SoD** y enviar: Operator + Approver queda `Rejected`, también con 202. La recepción no es la aprobación.
3. En el registro, usar **Repetir**: vuelve el mismo ID y no aumenta la evidencia.
4. Usar **Cambiar motivo**: produce 409 y no modifica el registro.
5. En **Evidencia & SHA-256**, verificar la cadena y probar una alteración en copia. Volver a verificar confirma que la evidencia original sigue intacta.
6. Explorar **Alcance técnico** y reiniciar al terminar.

## Correspondencia con el backend

Las operaciones, orden de roles, reglas SoD, validación de solicitudes e idempotencia siguen `SubmitRequest.cs`, `SodPolicyValidator.cs` e `InMemoryProvisioningStore.cs`. Las respuestas HTTP se simulan en el navegador; no prueban autenticación, red ni concurrencia del servidor.

El actor está fijo como `demo-technical-principal`, no representa un usuario humano autenticado. Solo existen estados `Pending` y `Rejected`. `ExpectedVersion` se valida y registra, pero no se contrasta con una cuenta real. Los reintentos comparan actor y contenido normalizado; las mayúsculas y espacios de los identificadores son significativos.

La demo usa SHA-256 real de Web Crypto, JSON UTF-8 y hashes hexadecimales en mayúsculas. `hashPayload` fija un esquema explícito `rbac-browser-demo-v1` con hash vacío y hash anterior incluido. No pretende reproducir byte a byte el serializador .NET ni importar evidencia de la API. Un enlace de hashes sin anclaje externo no detecta una reescritura completa ni un truncamiento final y no constituye almacenamiento WORM. La prueba de alteración opera sobre una copia.

Límite de presentación: 100 solicitudes únicas por pestaña. No hay persistencia, analítica ni envío de datos del formulario a servicios. Las fuentes se descargan desde Google Fonts, con alternativas locales. No introducir datos personales, claves ni tickets reales.

## Verificación

- Ocho pruebas automatizadas: validación, ambos conflictos SoD, replay normalizado, conflicto de actor/contenido, Disable, identificadores, alteración de evidencia y límite de demo.
- Chrome headless: formulario, reintentos, 409, filtros, verificación, alteración en copia, reinicio y responsive a 390 px, sin errores JS.
- Backend original: build sin errores/advertencias, 19 comprobaciones aprobadas y smoke HTTP con 63 eventos cuya cadena se recalcula desde Python. Ningún archivo funcional .NET fue modificado.

## Alojamiento

`dist/` se puede servir en cualquier alojamiento estático HTTPS. El push a este repositorio no publica automáticamente una versión de Sites. `.openai/hosting.json` conserva la identidad del sitio para futuras actualizaciones y no contiene credenciales.
