# Commercial License for IronSocketLayer

Copyright (C) 2026 NERVOSYS. All rights reserved.

## Dual licensing

IronSocketLayer (the crates `ironsocketlayer`, `isl-ontology` and `isl-cli`)
is available under two licences.

### 1. GNU Affero General Public License v3 (AGPL-3.0-or-later)

The default licence is the **GNU Affero General Public License v3**. Under it:

- You may use, copy, modify and distribute the software.
- If you modify it and make it available over a network, for example as a
  service, you **must** make the complete source of your modified version
  available to that service's users.
- Derivative works must also be licensed under the AGPL v3.
- Full text: [LICENSE](LICENSE).

For a TLS library the network clause reaches far. Linking IronSocketLayer
into a service that terminates or originates TLS makes that service a
derivative work, and the AGPL's source-disclosure obligation applies to it.

### 2. Commercial licence

A **commercial licence** is available from NERVOSYS if the AGPL does not fit
your use. For example, if you want to:

- integrate IronSocketLayer into proprietary or closed-source software;
- embed it in a shipped product, firmware image or device;
- distribute it without disclosing your source code;
- run it in a hosted service without AGPL obligations;
- receive dedicated support, warranty or indemnification.

**IronCrypto is licensed separately.** IronSocketLayer performs all of its
cryptography through [IronCrypto](https://github.com/nervosys/IronCrypto),
which is also AGPL-3.0-or-later with its own commercial option. Proprietary
use of IronSocketLayer therefore also needs a commercial IronCrypto licence.
Ask for both together.

## Obtaining a commercial licence

- **Email**: licensing@nervosys.ai
- **GitHub**: [github.com/nervosys](https://github.com/nervosys)

## What a licence does not cover

Neither licence makes a claim about assurance:

- **No FIPS validation.** Neither IronSocketLayer nor IronCrypto holds a CMVP
  certificate, and a commercial licence does not confer one. See
  [docs/FIPS.md](docs/FIPS.md).
- **No DO-178C certification.** See [docs/DO-178C.md](docs/DO-178C.md).
- **No independent review.** See [SECURITY.md](SECURITY.md).
- **Warranty.** The AGPL version comes without warranty, as the licence
  states. Any warranty or indemnification is set out in the commercial
  agreement, not here.

**Export.** Commercial distribution, as object code or as source that is not
publicly available, is not covered by the public-source notification under
15 CFR §742.15(b). It needs its own classification under License Exception
ENC before any such distribution; see [docs/EXPORT.md](docs/EXPORT.md).

## Contributor Licence Agreement

Contributors agree to the [Contributor License Agreement](CLA.md) before
their contributions are accepted. It lets contributions be distributed under
both the AGPL v3 and the commercial licence. See [CONTRIBUTING.md](CONTRIBUTING.md).
