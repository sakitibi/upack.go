package sencode

import (
	"errors"
	"fmt"
	"math"
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

	seed := m.GetSeed(m.SecretKey)
	rng := m.CreateRng(seed)

	m.InitialXor = int(math.Floor(rng() * 256))
	m.MagicSalt = int(math.Floor(rng() * 256))
	m.PoisonKey = int(math.Floor(rng()*7) + 1)

	m.LogicSequence = make([]int, 16)
	for i := 0; i < 16; i++ {
		m.LogicSequence[i] = int(math.Floor(rng() * 8))
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
			j := int(math.Floor(rng() * float64(i+1)))

			if ((i ^ offset) % 2) == 0 {
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
	morphSeed := m.GetSeed(morphKey)
	morphRng := m.CreateRng(morphSeed)

	freshWords := make([]string, len(BaseWords))
	copy(freshWords, BaseWords)

	m.executeShuffle(freshWords, morphRng)
	m.buildMapping(freshWords)
	return nil
}

func (m *SEncodeManager) GetSeed(key string) uint32 {
	keyBytes := []byte(key)
	combined := append(keyBytes, m.IV...)

	var h uint32 = 0x811c9dc5
	for _, b := range combined {
		h ^= uint32(b)
		h *= 0x01000193
	}
	return h
}

// TS版 (sencodeManager.ts) の LCG RNG と完全に一致させる
func (m *SEncodeManager) CreateRng(seed uint32) func() float64 {
	s := int32(seed)
	return func() float64 {
		s = s*1664525 + 1013904223
		unsigned := uint32(s)
		return float64(unsigned) / 4294967296.0
	}
}

// TS版と完全に一致する1バイト署名生成
func (m *SEncodeManager) GenerateSignature(data []byte) byte {
	sig := m.MagicSalt
	for i := 0; i < len(data); i++ {
		sig = ((sig ^ int(data[i])) * 0x01000193) & 0xFF
	}
	return byte(sig)
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
