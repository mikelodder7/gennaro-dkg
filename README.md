# gennaro-dkg

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache 2.0][license-image]
[![Build status](https://ci.appveyor.com/api/projects/status/cxxv4bng7ss5f09d?svg=true)](https://ci.appveyor.com/project/mikelodder7/vsss-rs)
[![Downloads][downloads-image]][crate-link]


The Gennaro Distributed Key Generation Algorithm as described [here](https://link.springer.com/content/pdf/10.1007/s00145-006-0347-3.pdf)

This implementation also mitigates the [Rogue Key Attack](https://blog.sigmaprime.io/dkg-rogue-key.html).

## Security Notes

This crate has received one security audit from Kudelski Security with no significant findings. The
audit report can be found [here](./audit/2024-15-02_LitProtoco_Crypto_Libraries_v1.1.pdf). We'd like to thank
[LIT Protocol](https://www.litprotocol.com) for sponsoring this audit.

## Protocol details

The protocol provided in this crate provides the following

- It will continue as long as there are enough participants a.k.a above the threshold
- Abort if the number of participants drops below the threshold

Malformed messages are not allowed and result in bad participants.
Non-responsive participants are out of scope for this crate since this includes timeouts and retries
which could be for a number of reasons: network latency, system crashes, etc. This is left to consumers
as is handling the creation a secure channel to send data.

Essentially communication channels are deliberately *not* part of this crate. The sending and receiving
of messages needs to be handled by the consumer of this crate. This allows the protocol to be used in 
both sync and async environments.

A good description of methods to do this can be found [here](https://medium.com/zengo/mpc-over-signal-977db599de66).

In a nut-shell:

1. Use Signal Protocol since this offers the highest security.
2. Use the latest version of TLS if you can rely on and trust PKI.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/gennaro-dkg.svg
[crate-link]: https://crates.io/crates/gennaro-dkg
[docs-image]: https://docs.rs/gennaro-dkg/badge.svg
[docs-link]: https://docs.rs/gennaro-dkg/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/gennaro-dkg.svg
