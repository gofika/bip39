[![codecov](https://codecov.io/gh/gofika/bip39/branch/main/graph/badge.svg)](https://codecov.io/gh/gofika/bip39)
[![Build Status](https://github.com/gofika/bip39/workflows/build/badge.svg)](https://github.com/gofika/bip39)
[![go.dev](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/gofika/bip39)
[![Go Report Card](https://goreportcard.com/badge/github.com/gofika/bip39)](https://goreportcard.com/report/github.com/gofika/bip39)
[![Licenses](https://img.shields.io/github/license/gofika/bip39)](LICENSE)

# bip39

A pure Golang implementation of the BIP39 protocol that automatically detects and supports mnemonic phrases in multiple languages.


## Basic Usage

### Installation

To get the package, execute:

```bash
go get github.com/gofika/bip39
```

### Example

```go
package main

import (
	"github.com/gofika/bip39"
)

func main() {
	// Detect for English
	{
		languages, ok := bip39.DetectLanguage("carbon elder drip best unlock pool athlete fortune mixture exist bachelor quick faculty obey cliff")
		if !ok {
			panic("invalid language")
		}
		if len(languages) != 1 || languages[0] != bip39.English {
			panic("invalid language")
		}
	}
	// Detect for Japanese
	{
		languages, ok := bip39.DetectLanguage("おさえる　けむり　けしごむ　うせつ　もちろん　とさか　いはつ　ざっか　たりる　こさめ　いわい　にいがた　こてい　ちんもく　がぞう")
		if !ok {
			panic("invalid language")
		}
		if len(languages) != 1 || languages[0] != bip39.Japanese {
			panic("invalid language")
		}
	}
	// Detect for ChineseSimplified and ChineseTraditional
	{
		languages, ok := bip39.DetectLanguage("露 水 域 耀 搜 船 良 摘 士 近 桃 案")
		if !ok {
			panic("invalid language")
		}
		if len(languages) != 2 {
			panic("invalid language")
		}
	}
	// Detect WithLanguages
	{
		languages, ok := bip39.DetectLanguage("露 水 域 耀 搜 船 良 摘 士 近 桃 案", bip39.WithLanguages([]bip39.Language{bip39.ChineseSimplified}))
		if !ok {
			panic("invalid language")
		}
		if len(languages) != 1 || languages[0] != bip39.ChineseSimplified {
			panic("invalid language")
		}
	}

	// NewMnemonic
	{
		// default language is English
		m, err := bip39.NewMnemonic()
		if err != nil {
			panic(err)
		}
		// default entropy 128 bits
		mnemonic, err := m.GenerateMnemonic()
		if err != nil {
			panic(err)
		}
		// default passphrase is empty
		seed := bip39.NewSeed(mnemonic)
		if len(seed) != 64 {
			panic("invalid seed")
		}
	}
	// NewMnemonic with Japanese
	{
		// generate mnemonic with Japanese
		m, err := bip39.NewMnemonic(bip39.WithLanguage(bip39.Japanese))
		if err != nil {
			panic(err)
		}
		// set entropy 256 bits
		mnemonic, err := m.GenerateMnemonic(bip39.WithEntropyBits(256))
		if err != nil {
			panic(err)
		}
		// set passphrase "gofika"
		seed := bip39.NewSeed(mnemonic, bip39.WithPassphrase("gofika"))
		if len(seed) != 64 {
			panic("invalid seed")
		}
	}
}
```