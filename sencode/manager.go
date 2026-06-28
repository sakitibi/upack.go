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
		hexKey := fmt.Sprintf("x%02x", targetPos)

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
	return binary.BigEndian.Uint32(hash[0:4])
}

func (m *SEncodeManager) CreateRng(seed uint32) func() float64 {
	x := seed
	if x == 0 {
		x = 88675123
	}
	return func() float64 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		return float64(x) / 4294967296.0
	}
}

func (m *SEncodeManager) GenerateSignature(data []byte) []byte {
	var h1 int64 = -2128831035
	var h2 int64 = 0x12345678

	for i := 0; i < len(data); i++ {
		h1_32 := int64(int32(h1))
		h1_32 ^= int64(data[i])
		h1 = h1_32 * 0x01000193

		h2_32 := int64(int32(h2))
		h2_32 ^= int64(int32(h1)) ^ int64(data[i])
		h2 = h2_32 * 0x0dcd1943
	}

	// 最終出力用に 32bit に固定
	finalH1 := uint32(int32(h1))
	finalH2 := uint32(int32(h2))

	sig := make([]byte, 16)
	binary.BigEndian.PutUint32(sig[0:4], finalH1)
	binary.BigEndian.PutUint32(sig[4:8], finalH2)
	binary.BigEndian.PutUint32(sig[8:12], finalH1^finalH2)
	binary.BigEndian.PutUint32(sig[12:16], finalH1+finalH2)
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
		return byte((((val ^ salt) ^ step) & 0xFF) & 0xFF)
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
