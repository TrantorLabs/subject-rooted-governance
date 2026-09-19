# Security boundary

This code exists to be broken on purpose. It exposes fault-injection entry points
(`ControlledLedger::fault_execute`, the scenario builders) and must not be deployed as a real
payment path, authorization boundary or identity service. Do not feed it real private keys, user
tokens or business data.

Source identifiers and observation seals are the experiment's trust contract, not credentials an
untrusted client can assert. A real integration needs an authenticated transport or verifiable
signatures in front of every evidence channel; `srg-soulauth` leaves that to the implementor of
`AuthenticatedFactTransport` for exactly this reason.

Nothing here is a guarantee about general AI controllability, cryptographic protocols or legal
liability. If you find a wrong verdict, keep the counterexample, the raw evidence file and the
tool versions, and report it at https://github.com/TrantorLabs/subject-rooted-governance/issues —
do not relabel the scenario to make the result look right.
