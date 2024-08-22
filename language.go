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

func splitMnemonic(mnemonic string) (words []string, delimiter string) {
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
