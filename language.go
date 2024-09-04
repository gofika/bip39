package bip39

import (
	"strings"

	"github.com/gofika/bip39/wordlists"
)

type Language byte

const (
	English Language = iota
	Japanese
	Korean
	Spanish
	ChineseSimplified
	ChineseTraditional
	French
	Italian
	Czech
	Portuguese
)

const (
	// Japanese uses ideographic spaces.
	japaneseSpace = '\u3000' // '　'
	// regular spaces.
	regularSpace = " "
)

var (
	delimiters = map[rune]struct{}{
		'\t': {},
		'\n': {},
		'\v': {},
		'\f': {},
		'\r': {},
		' ':  {},
	}
)

type languageData struct {
	words    []string
	wordsMap map[string]int
}

func innerLanguages() map[Language]languageData {
	return map[Language]languageData{
		English: {
			words:    wordlists.English,
			wordsMap: wordlists.EnglishMap,
		},
		Japanese: {
			words:    wordlists.Japanese,
			wordsMap: wordlists.JapaneseMap,
		},
		Korean: {
			words:    wordlists.Korean,
			wordsMap: wordlists.KoreanMap,
		},
		Spanish: {
			words:    wordlists.Spanish,
			wordsMap: wordlists.SpanishMap,
		},
		ChineseSimplified: {
			words:    wordlists.ChineseSimplified,
			wordsMap: wordlists.ChineseSimplifiedMap,
		},
		ChineseTraditional: {
			words:    wordlists.ChineseTraditional,
			wordsMap: wordlists.ChineseTraditionalMap,
		},
		French: {
			words:    wordlists.French,
			wordsMap: wordlists.FrenchMap,
		},
		Italian: {
			words:    wordlists.Italian,
			wordsMap: wordlists.ItalianMap,
		},
		Czech: {
			words:    wordlists.Czech,
			wordsMap: wordlists.CzechMap,
		},
		Portuguese: {
			words:    wordlists.Portuguese,
			wordsMap: wordlists.PortugueseMap,
		},
	}
}

// SplitMnemonic splits a mnemonic into words and delimiter.
// If the delimiter is a Japanese space, then the language must be Japanese.
//
// Example:
//
//	words, delimiter := SplitMnemonic("おさえる　けむり　けしごむ　うせつ　もちろん　とさか　いはつ　ざっか　たりる　こさめ　いわい　にいがた　こてい　ちんもく　がぞう")
//	fmt.Println(words) // ["おさえる", "けむり", "けしごむ", "うせつ", "もちろん", "とさか", "いはつ", "ざっか", "たりる", "こさめ", "いわい", "にいがた", "こてい", "ちんもく", "がぞう"]
//	fmt.Println(delimiter) // "　"
//
// Example:
//
//	words, delimiter := SplitMnemonic("carbon elder drip best unlock pool athlete fortune mixture exist bachelor quick faculty obey cliff")
//	fmt.Println(words) // ["carbon", "elder", "drip", "best", "unlock", "pool", "athlete", "fortune", "mixture", "exist", "bachelor", "quick", "faculty", "obey", "cliff"]
//	fmt.Println(delimiter) // " "
func SplitMnemonic(mnemonic string) (words []string, delimiter string) {
	delimiter = regularSpace
	words = strings.FieldsFunc(strings.TrimSpace(mnemonic), func(r rune) bool {
		if r == japaneseSpace {
			delimiter = string(r)
			return true
		}
		_, ok := delimiters[r]
		return ok
	})
	return
}

// NormalizeMnemonic normalizes the mnemonic.
//
// Example:
//
//	mnemonic := "おさえる　けむり　　けしごむ　うせつ　もちろん　　とさか　いはつ　ざっか　たりる　　こさめ　いわい　　にいがた　こてい　ちんもく　がぞう　"
//	mnemonic = NormalizeMnemonic(mnemonic)
//	fmt.Println(mnemonic) // おさえる　けむり　けしごむ　うせつ　もちろん　とさか　いはつ　ざっか　たりる　こさめ　いわい　にいがた　こてい　ちんもく　がぞう
//
// Example:
//
//	mnemonic := "carbon     elder  drip best unlock pool athlete   fortune mixture exist   bachelor quick faculty    obey cliff"
//	mnemonic = NormalizeMnemonic(mnemonic)
//	fmt.Println(mnemonic) // carbon elder drip best unlock pool athlete fortune mixture exist bachelor quick faculty obey cliff
func NormalizeMnemonic(mnemonic string) string {
	words, delimiter := SplitMnemonic(mnemonic)
	return strings.Join(words, delimiter)
}
