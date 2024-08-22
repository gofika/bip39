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
// The default entropy size is 16 bytes.
// If you want to set the entropy size, use WithEntropySize() option.
// The entropy size must be in [16, 20, 24, 28, 32].
func (m *Mnemonic) GenerateMnemonic(opts ...GenerateMnemonicOption) (string, error) {
	options := &GenerateMnemonicOptions{
		entropySize: 16,
	}
	for _, opt := range opts {
		opt(options)
	}
	if !validEntropySize(options.entropySize) {
		return "", ErrInvalidEntropy
	}
	entropy := make([]byte, options.entropySize)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", err
	}
	return m.EntropyToMnemonic(entropy)
}

// EntropyToMnemonic converts entropy to a mnemonic.
//
// The entropy must be in [16, 20, 24, 28, 32] bytes.
func (m *Mnemonic) EntropyToMnemonic(entropy []byte) (string, error) {
	if !validEntropySize(len(entropy)) {
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

// EntropyFromMnemonic converts a mnemonic to entropy.
func (m *Mnemonic) EntropyFromMnemonic(mnemonic string) ([]byte, error) {
	words, _ := splitMnemonic(mnemonic)
	wordsCount := len(words)
	if !validWordsSize(wordsCount) {
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

func validWordsSize(count int) bool {
	return slices.Contains(validWordsSizes, count)
}

var validEntropySizes = []int{16, 20, 24, 28, 32}

func validEntropySize(entropyLength int) bool {
	return slices.Contains(validEntropySizes, entropyLength)
}
