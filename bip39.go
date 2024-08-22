package bip39

import (
	"crypto/sha512"
	"slices"

	"golang.org/x/crypto/pbkdf2"
)

// NewSeed creates a hashed seed output given a provided string and password.
// No checking is performed to validate that the string provided is a valid mnemonic.
// default passphrase is empty string.
// if you want to set passphrase, use WithPassphrase() option.
func NewSeed(mnemonic string, opts ...NewSeedOption) []byte {
	options := &NewSeedOptions{}
	for _, opt := range opts {
		opt(options)
	}
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+options.passphrase), 2048, 64, sha512.New)
}

// IsMnemonicValid attempts to verify that the provided mnemonic is valid.
// Validity is determined by both the number of words being appropriate,
// and that all the words in the mnemonic are present in the word list.
func IsMnemonicValid(mnemonic string) bool {
	languages, ok := DetectLanguage(mnemonic)
	if !ok {
		return false
	}
	for _, lang := range languages {
		m, err := NewMnemonic(WithLanguage(lang))
		if err != nil {
			return false
		}
		_, err = m.EntropyFromMnemonic(mnemonic)
		if err != nil {
			return false
		}
	}
	return true
}

// DetectLanguage detect and return the languages of the mnemonic.
// Default all languages are possible.
// In some cases, multiple languages might be matched simultaneously, such as Simplified Chinese and Traditional Chinese.
// If you only want to perform detection within a specified list of languages. use WithLanguages() option.
func DetectLanguage(mnemonic string, opts ...DetectLanguageOption) (languages []Language, ok bool) {
	options := &DetectLanguageOptions{}
	for _, opt := range opts {
		opt(options)
	}
	possible := innerLanguages()
	if len(options.languages) > 0 {
		// If languages are specified, then only those languages are possible.
		for lang := range possible {
			if !slices.Contains(options.languages, lang) {
				delete(possible, lang)
			}
		}
	}
	words, delimiter := splitMnemonic(mnemonic)
	if delimiter == string(japaneseSpace) {
		// If the delimiter is a Japanese space, then the language must be Japanese.
		for lang := range possible {
			if lang != Japanese {
				delete(possible, lang)
			}
		}
	}
	for _, word := range words {
		for lang, data := range possible {
			if _, ok := data.wordsMap[word]; !ok {
				delete(possible, lang)
			}
		}
		if len(possible) == 1 {
			for lang := range possible {
				ok = true
				languages = append(languages, lang)
				return
			}
		}
	}
	ok = len(possible) > 0
	for lang := range possible {
		languages = append(languages, lang)
	}
	return
}
