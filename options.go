package bip39

// DetectLanguageOptions options for DetectLanguage function
type DetectLanguageOptions struct {
	// only those languages are possible
	languages []Language
}

// DetectLanguageOption a function that modifies DetectLanguageOptions
type DetectLanguageOption func(*DetectLanguageOptions)

// WithLanguages sets the languages to detect. If not set, all languages are possible.
func WithLanguages(languages []Language) func(*DetectLanguageOptions) {
	return func(options *DetectLanguageOptions) {
		options.languages = languages
	}
}

// NewSeedOptions options for NewSeed function
type NewSeedOptions struct {
	// passphrase is an optional passphrase used to generate the seed.
	passphrase string
}

// NewSeedOption a function that modifies NewSeedOptions
type NewSeedOption func(*NewSeedOptions)

// WithPassphrase sets the passphrase used to generate the seed.
func WithPassphrase(passphrase string) func(*NewSeedOptions) {
	return func(options *NewSeedOptions) {
		options.passphrase = passphrase
	}
}

// GenerateMnemonicOptions options for GenerateMnemonic function
type GenerateMnemonicOptions struct {
	// entropyBits is the bits of the entropy.
	entropyBits int
}

// GenerateMnemonicOption a function that modifies GenerateMnemonicOptions
type GenerateMnemonicOption func(*GenerateMnemonicOptions)

// WithEntropyBits sets the bits of the entropy.
func WithEntropyBits(entropyBits int) func(*GenerateMnemonicOptions) {
	return func(options *GenerateMnemonicOptions) {
		options.entropyBits = entropyBits
	}
}

// NewMnemonicOptions options for NewMnemonic function
type NewMnemonicOptions struct {
	// language is the language of the mnemonic.
	language Language
}

// NewMnemonicOption a function that modifies NewMnemonicOptions
type NewMnemonicOption func(*NewMnemonicOptions)

// WithLanguage sets the language of the mnemonic.
func WithLanguage(language Language) func(*NewMnemonicOptions) {
	return func(options *NewMnemonicOptions) {
		options.language = language
	}
}
