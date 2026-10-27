# Email matching and custom domain rules

GATES keeps two values for an accepted email:

- `deliveryEmail`: the exact address submitted and verified by the provider. Send mail and screen this value.
- `canonical`: the key used to detect an existing verified owner within one tenant. Do not use it as a delivery destination or authentication proof.

For example, the built-in Gmail policy maps `alex+trial@gmail.com` to `alex@gmail.com`, while preserving the submitted address for delivery. A canonical match can reject another account's claim; it cannot log a user into the existing account.

## Built-in behavior

GATES uses Mail Canon's strict parser and selected provider rules for Gmail, Microsoft, Proton and Fastmail. Other domains retain the submitted local part unless you configure a supported custom rule. Domain normalization does not imply that dots, case or plus tags are interchangeable on every mail system.

Do not infer an organization's mailbox behavior from its MX host. A domain hosted by a large provider can have different address semantics from that provider's consumer domains. Invalid or unsupported syntax rejects before an IronDome request. The GATES address/storage limit is 254 UTF-8 bytes.

## Add a rule for a domain you control

Only add transformations that the domain's mail system actually implements. Rules match an exact canonical domain, not subdomains or suffixes:

```ts
import { createEmailPolicy } from '@irondome-dev/gate';

const policy = createEmailPolicy({
  'company.example': { lowercase: true, stripPlusTag: true },
});
const email = policy.prepareEmail('Alex+trial@company.example');

console.log(email.canonical);
console.log(email.deliveryEmail);
```

Expected output:

```text
alex@company.example
Alex+trial@company.example
```

`company.example` represents a hypothetical mail system whose administrator has confirmed those equivalences. Do not copy that policy onto an unrelated production domain.

| Option | Effect on the local part | Default |
| --- | --- | --- |
| `stripPlusTag` | Removes the first `+` and the suffix after it. | `false` |
| `stripDots` | Removes ASCII dots. | `false` |
| `lowercase` | Lowercases the local part. | `false` |

GATES applies built-in rules first, then custom transformations. A custom rule cannot reverse a built-in equivalence. It rejects a transformation that produces an invalid mailbox.

Configure `canonicalRules` on a new engine, or pass a `createEmailPolicy(...)` result as `emailPolicy` to the online engine. Do not supply both. Adapters use the engine's policy; they do not need duplicate rule lists.

Rule keys are normalized at startup. Wildcards, duplicate normalized domains, unknown options and non-boolean values are rejected. The maximum is 256 domains. Configure built-in aliases under their canonical root, such as `gmail.com`, not `googlemail.com`.

## Change existing rules safely

A rule change can combine previously distinct keys or split one key into several. Do not restart existing tenants with a new rule object and relabel their stored keys. Use an [online policy migration](migration.md#change-the-policy-of-an-existing-gates-tenant).

The online engine retains verified originals to support later rule changes. Older canonical-only records cannot reconstruct removed characters. They need a current, trusted provider lookup or renewed verification. Collisions require an explicit ownership decision; GATES never chooses a winner or merges accounts.
