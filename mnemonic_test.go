package bip39

import (
	"strings"
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

func TestArbitraryEntropyToMnemonic(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		entropy       []byte
		expectedWords int
		shouldFail    bool
	}{
		{
			name:       "empty entropy",
			entropy:    []byte{},
			shouldFail: true,
		},
		{
			name:          "1 byte (8 bits) - padded to 32 bits",
			entropy:       []byte{0x42},
			expectedWords: 3,
		},
		{
			name:          "2 bytes (16 bits) - padded to 32 bits",
			entropy:       []byte{0x12, 0x34},
			expectedWords: 3,
		},
		{
			name:          "3 bytes (24 bits) - padded to 32 bits",
			entropy:       []byte{0x12, 0x34, 0x56},
			expectedWords: 3,
		},
		{
			name:          "4 bytes (32 bits) - no padding needed",
			entropy:       []byte{0x12, 0x34, 0x56, 0x78},
			expectedWords: 3,
		},
		{
			name:          "5 bytes (40 bits) - padded to 64 bits",
			entropy:       []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expectedWords: 6,
		},
		{
			name:          "8 bytes (64 bits) - no padding needed",
			entropy:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			expectedWords: 6,
		},
		{
			name:          "12 bytes (96 bits) - no padding needed",
			entropy:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
			expectedWords: 9,
		},
		{
			name:          "16 bytes (128 bits) - standard BIP39",
			entropy:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			expectedWords: 12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mnemonic, err := m.ArbitraryEntropyToMnemonic(tt.entropy)
			if tt.shouldFail {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			words, _ := SplitMnemonic(mnemonic)
			if len(words) != tt.expectedWords {
				t.Fatalf("expected %d words, got %d", tt.expectedWords, len(words))
			}

			// Verify all words are in the wordlist
			for _, word := range words {
				if _, ok := m.wordMap[word]; !ok {
					t.Fatalf("word %q not in wordlist", word)
				}
			}
		})
	}
}

func TestArbitraryEntropyDifferentLanguages(t *testing.T) {
	entropy := []byte{0x12, 0x34, 0x56}

	testCases := []struct {
		name string
		lang Language
	}{
		{"English", English},
		{"Japanese", Japanese},
		{"ChineseSimplified", ChineseSimplified},
		{"ChineseTraditional", ChineseTraditional},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewMnemonic(WithLanguage(tc.lang))
			if err != nil {
				t.Fatal(err)
			}

			mnemonic, err := m.ArbitraryEntropyToMnemonic(entropy)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", tc.name, err)
			}

			words, _ := SplitMnemonic(mnemonic)
			if len(words) != 3 {
				t.Fatalf("expected 3 words for %s, got %d", tc.name, len(words))
			}
		})
	}
}

func TestArbitraryEntropyPaddingBehavior(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	// Test that different inputs with the same padding result in different mnemonics
	entropy1 := []byte{0x01}                   // 8 bits -> padded to 32 bits
	entropy2 := []byte{0x01, 0x00, 0x00, 0x00} // 32 bits, same as padded entropy1

	mnemonic1, err := m.ArbitraryEntropyToMnemonic(entropy1)
	if err != nil {
		t.Fatal(err)
	}

	mnemonic2, err := m.ArbitraryEntropyToMnemonic(entropy2)
	if err != nil {
		t.Fatal(err)
	}

	// They should produce the same mnemonic since padding is with zeros
	if mnemonic1 != mnemonic2 {
		t.Fatalf("expected same mnemonic after padding: %q != %q", mnemonic1, mnemonic2)
	}
}

func TestArbitraryEntropyChecksumBits(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	// Test that changing a single bit in entropy produces a different mnemonic
	entropy1 := []byte{0x00, 0x00, 0x00, 0x00}
	entropy2 := []byte{0x00, 0x00, 0x00, 0x01}

	mnemonic1, err := m.ArbitraryEntropyToMnemonic(entropy1)
	if err != nil {
		t.Fatal(err)
	}

	mnemonic2, err := m.ArbitraryEntropyToMnemonic(entropy2)
	if err != nil {
		t.Fatal(err)
	}

	if mnemonic1 == mnemonic2 {
		t.Fatal("different entropy should produce different mnemonics")
	}
}

func TestArbitraryMnemonicToEntropy(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		entropy       []byte
		expectedWords int
		shouldFail    bool
	}{
		{
			name:          "4 bytes (32 bits)",
			entropy:       []byte{0x12, 0x34, 0x56, 0x78},
			expectedWords: 3,
		},
		{
			name:          "8 bytes (64 bits)",
			entropy:       []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			expectedWords: 6,
		},
		{
			name:          "12 bytes (96 bits)",
			entropy:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
			expectedWords: 9,
		},
		{
			name:          "16 bytes (128 bits)",
			entropy:       []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			expectedWords: 12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert entropy to mnemonic
			mnemonic, err := m.ArbitraryEntropyToMnemonic(tt.entropy)
			if err != nil {
				t.Fatalf("failed to convert entropy to mnemonic: %v", err)
			}

			// Verify word count
			words, _ := SplitMnemonic(mnemonic)
			if len(words) != tt.expectedWords {
				t.Fatalf("expected %d words, got %d", tt.expectedWords, len(words))
			}

			// Convert mnemonic back to entropy
			recoveredEntropy, err := m.ArbitraryMnemonicToEntropy(mnemonic)
			if err != nil {
				t.Fatalf("failed to convert mnemonic to entropy: %v", err)
			}

			// Compare entropy (should match the original)
			if len(recoveredEntropy) != len(tt.entropy) {
				t.Fatalf("entropy length mismatch: expected %d, got %d", len(tt.entropy), len(recoveredEntropy))
			}

			for i := range tt.entropy {
				if recoveredEntropy[i] != tt.entropy[i] {
					t.Fatalf("entropy mismatch at byte %d: expected %02x, got %02x", i, tt.entropy[i], recoveredEntropy[i])
				}
			}
		})
	}
}

func TestArbitraryEntropyRoundtrip(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		entropy    []byte
		paddedSize int // Expected size after padding
	}{
		{
			name:       "1 byte padded to 4 bytes",
			entropy:    []byte{0x42},
			paddedSize: 4,
		},
		{
			name:       "2 bytes padded to 4 bytes",
			entropy:    []byte{0x12, 0x34},
			paddedSize: 4,
		},
		{
			name:       "3 bytes padded to 4 bytes",
			entropy:    []byte{0x12, 0x34, 0x56},
			paddedSize: 4,
		},
		{
			name:       "4 bytes no padding",
			entropy:    []byte{0x12, 0x34, 0x56, 0x78},
			paddedSize: 4,
		},
		{
			name:       "5 bytes padded to 8 bytes",
			entropy:    []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			paddedSize: 8,
		},
		{
			name:       "7 bytes padded to 8 bytes",
			entropy:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			paddedSize: 8,
		},
		{
			name:       "8 bytes no padding",
			entropy:    []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			paddedSize: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert entropy to mnemonic
			mnemonic, err := m.ArbitraryEntropyToMnemonic(tt.entropy)
			if err != nil {
				t.Fatalf("failed to convert entropy to mnemonic: %v", err)
			}

			// Convert mnemonic back to entropy
			recoveredEntropy, err := m.ArbitraryMnemonicToEntropy(mnemonic)
			if err != nil {
				t.Fatalf("failed to convert mnemonic to entropy: %v", err)
			}

			// The recovered entropy should match the padded version
			if len(recoveredEntropy) != tt.paddedSize {
				t.Fatalf("recovered entropy length mismatch: expected %d, got %d", tt.paddedSize, len(recoveredEntropy))
			}

			// The original entropy bytes should match (plus zeros for padding)
			for i := 0; i < len(tt.entropy); i++ {
				if recoveredEntropy[i] != tt.entropy[i] {
					t.Fatalf("entropy mismatch at byte %d: expected %02x, got %02x", i, tt.entropy[i], recoveredEntropy[i])
				}
			}

			// The padding bytes should be zero
			for i := len(tt.entropy); i < tt.paddedSize; i++ {
				if recoveredEntropy[i] != 0 {
					t.Fatalf("padding byte at %d should be 0, got %02x", i, recoveredEntropy[i])
				}
			}

			// Verify we can convert back to the same mnemonic
			mnemonic2, err := m.ArbitraryEntropyToMnemonic(recoveredEntropy)
			if err != nil {
				t.Fatalf("failed to re-convert entropy to mnemonic: %v", err)
			}

			if mnemonic != mnemonic2 {
				t.Fatalf("mnemonic mismatch after roundtrip: %q != %q", mnemonic, mnemonic2)
			}
		})
	}
}

func TestArbitraryMnemonicToEntropyInvalidInputs(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		mnemonic string
		wantErr  error
	}{
		{
			name:     "empty mnemonic",
			mnemonic: "",
			wantErr:  ErrInvalidNumberWords,
		},
		{
			name:     "invalid word count (not multiple of 3)",
			mnemonic: "word word",
			wantErr:  ErrInvalidNumberWords,
		},
		{
			name:     "invalid word in mnemonic",
			mnemonic: "invalid fake notaword",
			wantErr:  ErrInvalidMnemonic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.ArbitraryMnemonicToEntropy(tt.mnemonic)
			if err == nil {
				t.Fatal("expected error but got none")
			}
			if err != tt.wantErr && tt.wantErr != nil {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestArbitraryEntropyChecksumValidation(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid mnemonic
	entropy := []byte{0x12, 0x34, 0x56, 0x78}
	mnemonic, err := m.ArbitraryEntropyToMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the mnemonic by changing the first word (entropy bytes)
	words, _ := SplitMnemonic(mnemonic)
	originalFirst := words[0]

	// Find a different word to use
	for _, word := range []string{"abandon", "ability", "able", "about", "above"} {
		if word != originalFirst {
			words[0] = word
			break
		}
	}

	corruptedMnemonic := strings.Join(words, " ")

	// Try to decode the corrupted mnemonic - should fail checksum
	_, err = m.ArbitraryMnemonicToEntropy(corruptedMnemonic)
	if err != ErrChecksumIncorrect {
		t.Fatalf("expected ErrChecksumIncorrect, got %v", err)
	}
}

func TestArbitraryEntropyLargerThan256Bits(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		entropySize   int // in bytes
		expectedWords int
	}{
		{
			name:          "32 bytes (256 bits) - standard BIP39 max",
			entropySize:   32,
			expectedWords: 24,
		},
		{
			name:          "36 bytes (288 bits) - beyond BIP39",
			entropySize:   36,
			expectedWords: 27,
		},
		{
			name:          "40 bytes (320 bits) - beyond BIP39",
			entropySize:   40,
			expectedWords: 30,
		},
		{
			name:          "48 bytes (384 bits) - beyond BIP39",
			entropySize:   48,
			expectedWords: 36,
		},
		{
			name:          "64 bytes (512 bits) - beyond BIP39",
			entropySize:   64,
			expectedWords: 48,
		},
		{
			name:          "100 bytes (800 bits) - large entropy",
			entropySize:   100,
			expectedWords: 75,
		},
		{
			name:          "128 bytes (1024 bits) - very large entropy",
			entropySize:   128,
			expectedWords: 96,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create entropy of specified size with a pattern
			entropy := make([]byte, tt.entropySize)
			for i := range entropy {
				entropy[i] = byte(i % 256)
			}

			// Convert to mnemonic
			mnemonic, err := m.ArbitraryEntropyToMnemonic(entropy)
			if err != nil {
				t.Fatalf("failed to convert entropy to mnemonic: %v", err)
			}

			// Verify word count
			words, _ := SplitMnemonic(mnemonic)
			if len(words) != tt.expectedWords {
				t.Fatalf("expected %d words, got %d", tt.expectedWords, len(words))
			}

			// Verify all words are valid
			for i, word := range words {
				if _, ok := m.wordMap[word]; !ok {
					t.Fatalf("word %d (%q) not in wordlist", i, word)
				}
			}

			// Convert back to entropy
			recoveredEntropy, err := m.ArbitraryMnemonicToEntropy(mnemonic)
			if err != nil {
				t.Fatalf("failed to convert mnemonic back to entropy: %v", err)
			}

			// Verify entropy matches
			if len(recoveredEntropy) != len(entropy) {
				t.Fatalf("entropy length mismatch: expected %d, got %d", len(entropy), len(recoveredEntropy))
			}

			for i := range entropy {
				if recoveredEntropy[i] != entropy[i] {
					t.Fatalf("entropy mismatch at byte %d: expected %02x, got %02x", i, entropy[i], recoveredEntropy[i])
				}
			}

			// Verify we can convert back to the same mnemonic
			mnemonic2, err := m.ArbitraryEntropyToMnemonic(recoveredEntropy)
			if err != nil {
				t.Fatalf("failed to re-convert entropy to mnemonic: %v", err)
			}

			if mnemonic != mnemonic2 {
				t.Fatalf("mnemonic mismatch after roundtrip")
			}
		})
	}
}

func TestArbitraryEntropyLargeWithPadding(t *testing.T) {
	m, err := NewMnemonic()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		entropySize   int // in bytes (will be padded)
		paddedSize    int
		expectedWords int
	}{
		{
			name:          "33 bytes padded to 36 bytes",
			entropySize:   33,
			paddedSize:    36,
			expectedWords: 27,
		},
		{
			name:          "50 bytes padded to 52 bytes",
			entropySize:   50,
			paddedSize:    52,
			expectedWords: 39,
		},
		{
			name:          "99 bytes padded to 100 bytes",
			entropySize:   99,
			paddedSize:    100,
			expectedWords: 75,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create entropy of specified size
			entropy := make([]byte, tt.entropySize)
			for i := range entropy {
				entropy[i] = byte((i * 7) % 256) // Different pattern
			}

			// Convert to mnemonic
			mnemonic, err := m.ArbitraryEntropyToMnemonic(entropy)
			if err != nil {
				t.Fatalf("failed to convert entropy to mnemonic: %v", err)
			}

			// Verify word count
			words, _ := SplitMnemonic(mnemonic)
			if len(words) != tt.expectedWords {
				t.Fatalf("expected %d words, got %d", tt.expectedWords, len(words))
			}

			// Convert back to entropy
			recoveredEntropy, err := m.ArbitraryMnemonicToEntropy(mnemonic)
			if err != nil {
				t.Fatalf("failed to convert mnemonic back to entropy: %v", err)
			}

			// Verify padded size
			if len(recoveredEntropy) != tt.paddedSize {
				t.Fatalf("padded entropy length mismatch: expected %d, got %d", tt.paddedSize, len(recoveredEntropy))
			}

			// Verify original bytes match
			for i := 0; i < tt.entropySize; i++ {
				if recoveredEntropy[i] != entropy[i] {
					t.Fatalf("entropy mismatch at byte %d: expected %02x, got %02x", i, entropy[i], recoveredEntropy[i])
				}
			}

			// Verify padding is zero
			for i := tt.entropySize; i < tt.paddedSize; i++ {
				if recoveredEntropy[i] != 0 {
					t.Fatalf("padding byte at %d should be 0, got %02x", i, recoveredEntropy[i])
				}
			}
		})
	}
}
