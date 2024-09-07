package bip39

import (
	"testing"
)

func TestMnemonic(t *testing.T) {
	possible := innerLanguages()
	for range 100 {
		for lang := range possible {
			m, err := NewMnemonic(WithLanguage(lang))
			if err != nil {
				t.Fatal(err)
			}
			mnemonic, err := m.GenerateMnemonic()
			if err != nil {
				t.Fatal(err)
			}
			if !IsMnemonicValid(mnemonic) {
				t.Fatal("invalid mnemonic")
			}
			entropy, err := m.EntropyFromMnemonic(mnemonic)
			if err != nil {
				t.Fatal(err)
			}
			mnemonic2, err := m.EntropyToMnemonic(entropy)
			if err != nil {
				t.Fatal(err)
			}
			if mnemonic != mnemonic2 {
				t.Fatal("mnemonic mismatch")
			}
		}
	}
}

func TestJPNMnemonic(t *testing.T) {
	m, err := NewMnemonic(WithLanguage(Japanese))
	if err != nil {
		t.Fatal(err)
	}
	mnemonic, err := m.GenerateMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	if !IsMnemonicValid(mnemonic) {
		t.Fatal("invalid mnemonic")
	}
}

func TestDelectLanguage(t *testing.T) {
	// Test for Japanese
	{
		languages, ok := DetectLanguage("おさえる　けむり　けしごむ　うせつ　もちろん　とさか　いはつ　ざっか　たりる　こさめ　いわい　にいがた　こてい　ちんもく　がぞう")
		if !ok {
			t.Fatal("invalid language")
		}
		if len(languages) != 1 || languages[0] != Japanese {
			t.Fatal("invalid language")
		}
	}
	// Test for English
	{
		languages, ok := DetectLanguage("carbon elder drip best unlock pool athlete fortune mixture exist bachelor quick faculty obey cliff")
		if !ok {
			t.Fatal("invalid language")
		}
		if len(languages) != 1 || languages[0] != English {
			t.Fatal("invalid language")
		}
	}
	// Test for ChineseSimplified and ChineseTraditional
	{
		languages, ok := DetectLanguage("露 水 域 耀 搜 船 良 摘 士 近 桃 案")
		if !ok {
			t.Fatal("invalid language")
		}
		if len(languages) != 2 {
			t.Fatal("invalid language")
		}
	}
	// Test WithLanguages
	{
		languages, ok := DetectLanguage("露 水 域 耀 搜 船 良 摘 士 近 桃 案", WithLanguages([]Language{ChineseSimplified}))
		if !ok {
			t.Fatal("invalid language")
		}
		if len(languages) != 1 || languages[0] != ChineseSimplified {
			t.Fatal("invalid language")
		}
	}
}

func TestNewSeed(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	mnemonic, err := m.GenerateMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	seed := NewSeed(mnemonic)
	if len(seed) != 64 {
		t.Fatal("invalid seed")
	}

	// NewMnemonic with Japanese
	{
		// generate mnemonic with Japanese
		m, err := NewMnemonic(WithLanguage(Japanese))
		if err != nil {
			t.Fatal(err)
		}
		// set entropy 256 bits
		mnemonic, err := m.GenerateMnemonic(WithEntropyBits(256))
		if err != nil {
			t.Fatal(err)
		}
		// set passphrase "gofika"
		seed := NewSeed(mnemonic, WithPassphrase("gofika"))
		if len(seed) != 64 {
			t.Fatal("invalid seed")
		}
	}
}
