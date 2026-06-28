package sencode

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

type SEncodeManager struct {
	ConversionMap map[string]string
	ReverseMap    map[string]int
	JunkWords     []string
	InitialXor    int
	MagicSalt     int
	PoisonKey     int
	LogicSequence []int
	SecretKey     string
	IV            []byte
}

func NewSEncodeManager(secretKey string, iv []byte) *SEncodeManager {
	if secretKey == "" {
		secretKey = "default"
	}
	return &SEncodeManager{
		SecretKey:     secretKey,
		IV:            iv,
		ConversionMap: make(map[string]string),
		ReverseMap:    make(map[string]int),
	}
}

func (m *SEncodeManager) Initialize() error {
	if len(BaseWords) < 256 {
		return errors.New("BASE_WORDS不足")
	}

	seed := m.deriveSecureSeed(m.SecretKey, m.IV)
	rng := m.CreateRng(seed)

	m.InitialXor = int(uint32(rng()*256) & 0xFF)
	m.MagicSalt = int(uint32(rng()*256) & 0xFF)
	m.PoisonKey = int((uint32(rng()*7) & 0xFF) + 1)

	m.LogicSequence = make([]int, 16)
	for i := 0; i < 16; i++ {
		m.LogicSequence[i] = int(uint32(rng()*8) & 0xFF)
	}

	words := make([]string, len(BaseWords))
	copy(words, BaseWords)

	m.executeShuffle(words, rng)
	m.buildMapping(words)
	return nil
}

func (m *SEncodeManager) executeShuffle(words []string, rng func() float64) {
	length := len(words)
	for pass := 0; pass < 2; pass++ {
		for i := length - 1; i > 0; i-- {
			offset := m.LogicSequence[i%len(m.LogicSequence)]
			j := int(rng() * float64(i+1))

			// JSの優先順位: % は ^ より高いため `i ^ (offset % 2) == 0` が正しい挙動です
			if (i ^ (offset % 2)) == 0 {
				j = (j + offset) % (i + 1)
			}

			words[i], words[j] = words[j], words[i]

			if i%32 == 0 {
				charSum := 0
				for _, r := range words[i] {
					charSum += int(r)
				}
				if (charSum & 0xFF) > 128 {
					rng()
				}
			}
		}
	}
}

func (m *SEncodeManager) buildMapping(words []string) {
	m.ConversionMap = make(map[string]string)
	m.ReverseMap = make(map[string]int)
	assignedIndices := make(map[int]bool)
	currentIdx := m.LogicSequence[0]

	for i := 0; i < 256; i++ {
		step := m.LogicSequence[i%16] + 1

		for assignedIndices[currentIdx%256] {
			currentIdx++
		}

		targetPos := currentIdx % 256
		hexKey := fmt.Sprintf("x%02x", targetPos&0xFF)

		m.ConversionMap[hexKey] = words[i]
		m.ReverseMap[words[i]] = targetPos
		assignedIndices[targetPos] = true

		currentIdx += step
	}

	m.JunkWords = words[256:]
}

func (m *SEncodeManager) DynamicMorphTable(separatorCount int) error {
	morphKey := fmt.Sprintf("%s_morph_token_%d", m.SecretKey, separatorCount)
	morphSeed := m.deriveSecureSeed(morphKey, m.IV)
	morphRng := m.CreateRng(morphSeed)

	freshWords := make([]string, len(BaseWords))
	copy(freshWords, BaseWords)

	m.executeShuffle(freshWords, morphRng)
	m.buildMapping(freshWords)
	return nil
}

func (m *SEncodeManager) deriveSecureSeed(key string, iv []byte) uint32 {
	keyBytes := []byte(key)
	combined := append(keyBytes, iv...)

	hash := sha256.Sum256(combined)
	// TS側の `new Uint32Array(hashBuffer)[0]` はリトルエンディアン（x86/ARM環境）になるためLittleEndianで解釈
	return binary.LittleEndian.Uint32(hash[0:4])
}

// ★ JSのビット演算(>>> 17 の完全論理シフト再現)を修正
func (m *SEncodeManager) CreateRng(seed uint32) func() float64 {
	x := int32(seed)
	if x == 0 {
		x = 88675123
	}
	return func() float64 {
		x ^= x << 13
		x ^= int32(uint32(x) >> 17) // ★ここを int32(uint32(x) >> 17) にすることで JSの >>> 17 と完全同期
		x ^= x << 5
		return float64(uint32(x)) / 4294967296.0
	}
}

func (m *SEncodeManager) GenerateSignature(data []byte) []byte {
	var h1 int32 = -2128831035 // 0x811c9dc5 の符号付き整数表現
	var h2 int32 = 0x12345678

	for i := 0; i < len(data); i++ {
		d := int32(data[i])
		h1 ^= d
		h1 = h1 * 0x01000193
		h2 ^= h1 ^ d
		h2 = h2 * 0x0dcd1943
	}

	sig := make([]byte, 16)
	// JS側の DataView は明示的に BigEndian (false) 指定されているため、ここをBigEndianに統一
	binary.BigEndian.PutUint32(sig[0:4], uint32(h1))
	binary.BigEndian.PutUint32(sig[4:8], uint32(h2))
	binary.BigEndian.PutUint32(sig[8:12], uint32(h1^h2))
	binary.BigEndian.PutUint32(sig[12:16], uint32(h1+h2))
	return sig
}

func (m *SEncodeManager) ApplyLogic(val, xor, salt, step int) byte {
	mode := m.LogicSequence[step%len(m.LogicSequence)]
	switch mode {
	case 0:
		return byte((val ^ xor ^ salt) & 0xFF)
	case 1:
		return byte((val + xor + salt) & 0xFF)
	case 2:
		return byte(((val ^ salt) - xor) & 0xFF)
	case 3:
		return byte(((val - salt) ^ xor) & 0xFF)
	case 4:
		return byte((val ^ (xor + salt)) & 0xFF)
	case 5:
		// JSの優先順位: ^ は & より高いため `((val ^ salt) ^ step) & 0xFF` が正しい挙動
		return byte(((val ^ salt) ^ step) & 0xFF)
	default:
		return byte((val ^ xor) & 0xFF)
	}
}

func (m *SEncodeManager) ReverseLogic(val, xor, salt, step int) byte {
	mode := m.LogicSequence[step%len(m.LogicSequence)]
	switch mode {
	case 0:
		return byte((val ^ xor ^ salt) & 0xFF)
	case 1:
		return byte((val - xor - salt) & 0xFF)
	case 2:
		return byte(((val + xor) ^ salt) & 0xFF)
	case 3:
		return byte(((val ^ xor) + salt) & 0xFF)
	case 4:
		return byte((val ^ (xor + salt)) & 0xFF)
	case 5:
		return byte((val ^ step ^ salt) & 0xFF)
	default:
		return byte((val ^ xor) & 0xFF)
	}
}
