package bip39

import (
	"slices"
	"testing"
)

func TestSplitMnemonic(t *testing.T) {
	words, delimiter := SplitMnemonic("おさえる　けむり　けしごむ　うせつ　もちろん　とさか　いはつ　ざっか　たりる　こさめ　いわい　にいがた　こてい　ちんもく　がぞう")
	if len(words) != 15 || delimiter != "　" {
		t.Fatal("invalid words or delimiter")
	}
	if !slices.Equal(words, []string{"おさえる", "けむり", "けしごむ", "うせつ", "もちろん", "とさか", "いはつ", "ざっか", "たりる", "こさめ", "いわい", "にいがた", "こてい", "ちんもく", "がぞう"}) {
		t.Fatal("invalid words")
	}

	words, delimiter = SplitMnemonic("carbon elder drip best unlock pool athlete fortune mixture exist bachelor quick faculty obey cliff")
	if len(words) != 15 || delimiter != " " {
		t.Fatal("invalid words or delimiter")
	}
	if !slices.Equal(words, []string{"carbon", "elder", "drip", "best", "unlock", "pool", "athlete", "fortune", "mixture", "exist", "bachelor", "quick", "faculty", "obey", "cliff"}) {
		t.Fatal("invalid words")
	}
}

func TestNormalizeMnemonic(t *testing.T) {
	mnemonic := "おさえる　けむり　　  けしごむ　うせつ　もちろん　　とさか　いはつ　ざっか　たりる　　こさめ　いわい　　にいがた　こてい　ちんもく　がぞう　  "
	mnemonic = NormalizeMnemonic(mnemonic)
	if mnemonic != "おさえる　けむり　けしごむ　うせつ　もちろん　とさか　いはつ　ざっか　たりる　こさめ　いわい　にいがた　こてい　ちんもく　がぞう" {
		t.Fatal("invalid mnemonic")
	}

	mnemonic = "carbon     elder  drip best unlock pool athlete   fortune mixture exist   bachelor quick faculty    obey cliff  "
	mnemonic = NormalizeMnemonic(mnemonic)
	if mnemonic != "carbon elder drip best unlock pool athlete fortune mixture exist bachelor quick faculty obey cliff" {
		t.Fatal("invalid mnemonic")
	}
}
