# Playbook: Insecure Deserialization & SSTI

Two distinct classes that both turn attacker data into server-side execution.
Grouped because both are "the server evaluated something it should have treated
as inert data," and both are high-to-critical when they land.

## A. Insecure Deserialization -> RCE

Where the app deserializes attacker-controlled bytes:
- **Java:** `rO0` (base64) / `\xac\xed\x00\x05` (raw) magic bytes in cookies,
  hidden fields, `viewstate`, RMI/JMX. -> ysoserial gadget chains.
- **PHP:** `unserialize()` on user input; look for `O:` / `a:` serialized strings
  in cookies/params. -> POP chains via `__wakeup`/`__destruct`.
- **Python:** `pickle.loads`, `yaml.load` (unsafe), `jsonpickle`. -> `__reduce__`
  gives arbitrary code.
- **.NET:** `BinaryFormatter`, `LosFormatter`, JSON.NET `TypeNameHandling`.
- **Node:** `node-serialize`, some `funcster`/`serialize-javascript` misuse.

**Method:** identify the format (magic bytes / structure), confirm the sink reads
your bytes, then prove execution out-of-band first — a gadget that does a DNS/HTTP
callback to your `oob_start()` domain proves RCE without dropping a payload.
Escalate to a command only on a target where that's authorized and safe.

## B. SSTI (Server-Side Template Injection)

User input rendered as a template instead of data. Test any reflected value with
per-engine probes:
- Polyglot: `${{7*7}}` / `{{7*7}}` / `<%= 7*7 %>` / `#{7*7}`. A `49` in the
  response = template evaluation.
- **Jinja2 (Python):** `{{7*7}}` -> 49, then `{{config}}`, then the
  `__class__.__mro__` -> subprocess RCE chain.
- **Twig/PHP:** `{{7*7}}`, `_self.env` gadgets.
- **Freemarker/Velocity (Java):** `<#assign>` / `#set`, `Runtime.exec`.
- **ERB (Ruby):** `<%= %>`.

**Method:** find reflection -> confirm arithmetic evaluates -> fingerprint engine
by which syntax fires -> escalate to file read / RCE with the engine's known
chain, proving OOB first.

## Report
Name the exact engine/format, show the probe (`{{7*7}}`->49 or the gadget) and the
proof (OOB callback for RCE, or the evaluated output). Remediation: never
deserialize untrusted data (use JSON + a schema); never render user input as a
template — pass it as a context variable to a sandboxed engine.
