package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

var (
	ErrInvalidEntropy       = errors.New("invalid entropy")
	ErrInvalidMnemonic      = errors.New("invalid mnemonic")
	ErrInvalidNumberWords   = errors.New("invalid number of words")
	ErrInvalidNumberEntropy = errors.New("invalid number of entropy")
	ErrChecksumIncorrect    = errors.New("checksum incorrect")
)

var (
	// Some bitwise operands for working with big.Ints
	shift11BitsMask = big.NewInt(2048)
	bigOne          = big.NewInt(1)

	// used to isolate the checksum bits from the entropy+checksum byte array
	wordLengthChecksumMasks = map[int]*big.Int{
		12: big.NewInt(15),
		15: big.NewInt(31),
		18: big.NewInt(63),
		21: big.NewInt(127),
		24: big.NewInt(255),
	}

	// used to use only the desired x of 8 available checksum bits.
	// 256 bit (word length 24) requires all 8 bits of the checksum,
	// and thus no shifting is needed for it (we would get a divByZero crash if we did)
	wordLengthChecksumShifts = map[int]*big.Int{
		12: big.NewInt(16),
		15: big.NewInt(8),
		18: big.NewInt(4),
		21: big.NewInt(2),
	}
)

// Mnemonic
type Mnemonic struct {
	wordList  []string
	wordMap   map[string]int
	delimiter string
}

// NewMnemonic creates a new Mnemonic instance.
//
// The default language is English.
// If you want to set the language, use WithLanguage() option.
func NewMnemonic(opts ...NewMnemonicOption) (*Mnemonic, error) {
	options := &NewMnemonicOptions{
		language: English,
	}
	for _, opt := range opts {
		opt(options)
	}
	delimiter := " "
	language := options.language
	if language == Japanese {
		delimiter = string(japaneseSpace)
	}

	possible := innerLanguages()
	data, ok := possible[language]
	if !ok {
		return nil, fmt.Errorf("language %d not supported", language)
	}

	return &Mnemonic{
		wordList:  data.words,
		wordMap:   data.wordsMap,
		delimiter: delimiter,
	}, nil
}

// GenerateMnemonic generates a new mnemonic.
//
// The default entropy bits is 128.
// If you want to set the entropy bits, use WithEntropyBits() option.
// The entropy bits must be in [128, 160, 192, 224, 256].
// Corresponding to [16, 20, 24, 28, 32] bytes.
func (m *Mnemonic) GenerateMnemonic(opts ...GenerateMnemonicOption) (string, error) {
	options := &GenerateMnemonicOptions{
		entropyBits: 128,
	}
	for _, opt := range opts {
		opt(options)
	}
	if !isValidEntropyBits(options.entropyBits) {
		return "", ErrInvalidEntropy
	}
	entropySize := options.entropyBits / 8
	entropy := make([]byte, entropySize)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", err
	}
	return m.EntropyToMnemonic(entropy)
}

// EntropyToMnemonic converts entropy to a mnemonic.
//
// The entropy must be in [16, 20, 24, 28, 32] bytes.
// Corresponding to [128, 160, 192, 224, 256] bits.
func (m *Mnemonic) EntropyToMnemonic(entropy []byte) (string, error) {
	if !isValidEntropyBits(len(entropy) * 8) {
		return "", ErrInvalidEntropy
	}

	checksum, err := computeChecksum(entropy)
	if err != nil {
		return "", err
	}
	entropyWithChecksum := append(entropy, checksum)

	var words []string
	for i := 0; i < len(entropyWithChecksum)*8/11; i++ {
		index := extractBits(entropyWithChecksum, i*11, 11)
		words = append(words, m.wordList[index])
	}

	return strings.Join(words, m.delimiter), nil
}

// ArbitraryEntropyToMnemonic converts arbitrary length entropy to a mnemonic.
// This is NOT strict BIP39 compliant. Use this for custom applications that need
// to encode payloads smaller than 128 bits or of arbitrary length.
//
// If the entropy is not a multiple of 32 bits (4 bytes), it will be padded with
// zero bytes to the next 32-bit boundary. The minimum size after padding is 4 bytes (32 bits).
//
// The resulting mnemonic will have a number of words based on the padded entropy size:
// - 4 bytes (32 bits) + 1 checksum bit = 3 words
// - 8 bytes (64 bits) + 2 checksum bits = 6 words
// - 12 bytes (96 bits) + 3 checksum bits = 9 words
// - 16 bytes (128 bits) + 4 checksum bits = 12 words (standard BIP39)
// - etc.
func (m *Mnemonic) ArbitraryEntropyToMnemonic(entropy []byte) (string, error) {
	if len(entropy) == 0 {
		return "", ErrInvalidEntropy
	}

	// Pad to next 32-bit boundary if needed
	entropyBits := len(entropy) * 8
	remainder := entropyBits % 32
	if remainder != 0 {
		paddingBytes := (32 - remainder) / 8
		entropy = append(entropy, make([]byte, paddingBytes)...)
	}

	// Compute checksum based on padded entropy
	checksum, err := computeChecksum(entropy)
	if err != nil {
		return "", err
	}

	// Calculate how many checksum bits we need (1 bit per 32 bits of entropy)
	checksumBits := len(entropy) / 4

	// We need to append enough checksum bytes to cover all checksum bits
	// For every 8 checksum bits, we need 1 byte
	checksumBytes := (checksumBits + 7) / 8
	entropyWithChecksum := make([]byte, len(entropy)+checksumBytes)
	copy(entropyWithChecksum, entropy)
	
	// Fill in the checksum bytes
	for i := 0; i < checksumBytes; i++ {
		entropyWithChecksum[len(entropy)+i] = checksum
	}

	// Calculate number of words (each word is 11 bits)
	totalBits := len(entropy)*8 + checksumBits
	wordCount := totalBits / 11

	var words []string
	for i := 0; i < wordCount; i++ {
		index := extractBits(entropyWithChecksum, i*11, 11)
		words = append(words, m.wordList[index])
	}

	return strings.Join(words, m.delimiter), nil
}

// ArbitraryMnemonicToEntropy converts a mnemonic created with ArbitraryEntropyToMnemonic
// back to entropy bytes. This is the reverse operation of ArbitraryEntropyToMnemonic.
//
// This is NOT strict BIP39 compliant. The returned entropy will be padded to a 32-bit
// boundary (matching what ArbitraryEntropyToMnemonic does).
//
// Supported word counts: 3, 6, 9, 12, 15, 18, 21, 24 words
// - 3 words = 4 bytes (32 bits)
// - 6 words = 8 bytes (64 bits)
// - 9 words = 12 bytes (96 bits)
// - 12 words = 16 bytes (128 bits) (standard BIP39)
// - etc.
func (m *Mnemonic) ArbitraryMnemonicToEntropy(mnemonic string) ([]byte, error) {
	words, _ := SplitMnemonic(mnemonic)
	wordsCount := len(words)

	// For arbitrary entropy, we support word counts that are multiples of 3
	if wordsCount == 0 || wordsCount%3 != 0 {
		return nil, ErrInvalidNumberWords
	}

	// Calculate entropy size: each 3 words = 4 bytes (32 bits) of entropy + 1 checksum bit
	entropySize := (wordsCount / 3) * 4
	checksumBits := entropySize / 4

	// Decode the words into a big.Int
	b := big.NewInt(0)
	for _, word := range words {
		index, ok := m.wordMap[word]
		if !ok {
			return nil, ErrInvalidMnemonic
		}
		var wordBytes [2]byte
		binary.BigEndian.PutUint16(wordBytes[:], uint16(index))
		b = b.Mul(b, shift11BitsMask)
		b = b.Or(b, big.NewInt(0).SetBytes(wordBytes[:]))
	}

	// Extract checksum bits
	checksumMask := big.NewInt((1 << checksumBits) - 1)
	checksum := big.NewInt(0)
	checksum = checksum.And(b, checksumMask)

	// Remove checksum bits to get entropy
	b.Div(b, big.NewInt(0).Add(checksumMask, bigOne))

	// The entropy is the underlying bytes of the big.Int
	entropy := b.Bytes()
	entropy = padByteSlice(entropy, entropySize)

	// Verify the checksum
	entropyChecksumByte, err := computeChecksum(entropy)
	if err != nil {
		return nil, err
	}

	// Extract the needed checksum bits from the computed checksum
	// For checksumBits <= 8, we shift and compare directly
	// For checksumBits > 8, we only use the high-order bits that fit in one byte
	var entropyChecksum *big.Int
	if checksumBits <= 8 {
		checksumShift := 8 - checksumBits
		entropyChecksum = big.NewInt(int64(entropyChecksumByte >> checksumShift))
	} else {
		// When we have more than 8 checksum bits, we only use the first 8 bits
		// The checksum repeats the same byte pattern
		entropyChecksum = big.NewInt(int64(entropyChecksumByte))
		// Shift left to account for the additional bits beyond 8
		additionalBits := checksumBits - 8
		entropyChecksum.Lsh(entropyChecksum, uint(additionalBits))
		// Add the remaining bits (same byte repeated)
		for i := 0; i < additionalBits; i++ {
			bit := (entropyChecksumByte >> (7 - (i % 8))) & 1
			if bit == 1 {
				entropyChecksum.SetBit(entropyChecksum, additionalBits-1-i, 1)
			}
		}
	}

	if checksum.Cmp(entropyChecksum) != 0 {
		return nil, ErrChecksumIncorrect
	}

	return entropy, nil
}

// EntropyFromMnemonic converts a mnemonic to entropy.
func (m *Mnemonic) EntropyFromMnemonic(mnemonic string) ([]byte, error) {
	words, _ := SplitMnemonic(mnemonic)
	wordsCount := len(words)
	if !isValidWordsSize(wordsCount) {
		return nil, ErrInvalidNumberWords
	}

	// Decode the words into a big.Int.
	b := big.NewInt(0)
	for _, word := range words {
		index, ok := m.wordMap[word]
		if !ok {
			return nil, ErrInvalidMnemonic
		}
		var wordBytes [2]byte
		binary.BigEndian.PutUint16(wordBytes[:], uint16(index))
		b = b.Mul(b, shift11BitsMask)
		b = b.Or(b, big.NewInt(0).SetBytes(wordBytes[:]))
	}

	// Build and add the checksum to the big.Int.
	checksum := big.NewInt(0)
	checksumMask := wordLengthChecksumMasks[wordsCount]
	checksum = checksum.And(b, checksumMask)

	b.Div(b, big.NewInt(0).Add(checksumMask, bigOne))

	// The entropy is the underlying bytes of the big.Int. Any upper bytes of
	// all 0's are not returned so we pad the beginning of the slice with empty
	// bytes if necessary.
	entropy := b.Bytes()
	entropy = padByteSlice(entropy, wordsCount/3*4)

	// Generate the checksum and compare with the one we got from the mneomnic.
	entropyChecksumByte, err := computeChecksum(entropy)
	if err != nil {
		return nil, err
	}
	entropyChecksum := big.NewInt(int64(entropyChecksumByte))
	if l := wordsCount; l != 24 {
		checksumShift := wordLengthChecksumShifts[l]
		entropyChecksum.Div(entropyChecksum, checksumShift)
	}

	if checksum.Cmp(entropyChecksum) != 0 {
		return nil, ErrChecksumIncorrect
	}
	return entropy, nil
}

func computeChecksum(entropy []byte) (byte, error) {
	h := sha256.New()
	if _, err := h.Write(entropy); err != nil {
		return 0, err
	}
	return h.Sum(nil)[0], nil
}

func extractBits(data []byte, start, length int) int {
	var result int
	for i := 0; i < length; i++ {
		byteIndex := (start + i) / 8
		bitIndex := (start + i) % 8
		result = (result << 1) | int((data[byteIndex]>>(7-bitIndex))&1)
	}
	return result
}

// padByteSlice returns a byte slice of the given size with contents of the
// given slice left padded and any empty spaces filled with 0's.
func padByteSlice(slice []byte, length int) []byte {
	offset := length - len(slice)
	if offset <= 0 {
		return slice
	}
	newSlice := make([]byte, length)
	copy(newSlice[offset:], slice)
	return newSlice
}

// func normalizeString(s string) string {
// 	return norm.NFKD.String(s)
// }

var validWordsSizes = []int{12, 15, 18, 21, 24}

func isValidWordsSize(count int) bool {
	return slices.Contains(validWordsSizes, count)
}

var validEntropyBits = []int{128, 160, 192, 224, 256}

func isValidEntropyBits(entropyBits int) bool {
	return slices.Contains(validEntropyBits, entropyBits)
}
