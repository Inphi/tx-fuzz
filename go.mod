module github.com/MariusVanDerWijden/tx-fuzz

go 1.16

require (
	github.com/MariusVanDerWijden/FuzzyVM v0.0.0-20221202121132-bd37e8fb1d0d
	github.com/ethereum/go-ethereum v1.10.26
	github.com/holiman/goevmlab v0.0.0-20221207202144-89074274e1b7
	github.com/urfave/cli/v2 v2.23.7
)

replace github.com/ethereum/go-ethereum v1.10.26 => github.com/ethereum-optimism/op-geth v1.11.2-de8c5df46.0.20230324105532-555b76f39878
