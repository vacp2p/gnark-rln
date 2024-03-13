# g-rln

gnark implementation of rln-v2. super hacky and unclean.

Need to get test vectors for other backends, but bn254 works with the kats from [zerokit](https://github.com/vacp2p/zerokit/blob/8614b2a33a295921aef30129b9fc3cf6d5710c9d/rln/tests/protocol.rs#L240)

Poseidon implementation taken from [here](https://raw.githubusercontent.com/AlpinYukseloglu/poseidon-gnark/main/circuits/poseidon.go)

Merkle tree Inclusion proof taken from [here](https://github.com/reilabs/gnark-lean-demo/blob/a3955946e0d5f63d8bdc4e5bb2a60d0ba613544c/go-circuit/semaphore.go#L31)

## Usage

```bash
go run main.go
```