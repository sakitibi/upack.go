package sencode

import (
	"errors"
	"math"
	"math/rand"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type SEncodeMapProps map[string]string
type SDecodeMapProps map[string]int

type SEncodeManager struct {
	ConversionMap SEncodeMapProps
	ReverseMap    SDecodeMapProps
	JunkWords     []string
	InitialXor    int
	MagicSalt     int
	PoisonKey     int
	LogicSequence []int
	secretKey     string
}

func NewSEncodeManager(secretKey string) (*SEncodeManager, error) {
	if secretKey == "" {
		secretKey = "default"
	}
	manager := &SEncodeManager{
		secretKey: secretKey,
	}
	err := manager.initializeMaps(secretKey)
	if err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *SEncodeManager) initializeMaps(secretKey string) error {
	if len(BaseWords) < 256 {
		return errors.New("BASE_WORDS不足")
	}

	seed := m.GetSeed(secretKey)
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

			if (i^offset)%2 == 0 {
				j = (j + offset) % (i + 1)
			}

			words[i], words[j] = words[j], words[i]

			if i%32 == 0 {
				charSum := 0
				for _, c := range words[i] {
					charSum += int(c)
				}
				if (charSum & 0xFF) > 128 {
					rng()
				}
			}
		}
	}
}

func (m *SEncodeManager) buildMapping(words []string) {
	m.ConversionMap = make(SEncodeMapProps)
	m.ReverseMap = make(SDecodeMapProps)
	assignedIndices := make(map[int]bool)
	currentIdx := m.LogicSequence[0]

	for i := 0; i < 256; i++ {
		step := m.LogicSequence[i%16] + 1

		for assignedIndices[currentIdx%256] {
			currentIdx++
		}

		targetPos := currentIdx % 256
		hexKey := "x" + strconv.FormatInt(int64(targetPos), 16)
		if len(hexKey) == 2 { // "x" + 1文字の場合、"x0"の形にするためパディング
			hexKey = "x0" + hexKey[1:]
		}

		m.ConversionMap[hexKey] = words[i]
		m.ReverseMap[words[i]] = targetPos
		assignedIndices[targetPos] = true

		currentIdx += step
	}

	m.JunkWords = words[256:]
}

func (m *SEncodeManager) DynamicMorphTable(separatorCount int) {
	morphSeed := m.GetSeed(m.secretKey + "_morph_token_" + strconv.Itoa(separatorCount))
	morphRng := m.CreateRng(morphSeed)

	freshWords := make([]string, len(BaseWords))
	copy(freshWords, BaseWords)

	m.executeShuffle(freshWords, morphRng)
	m.buildMapping(freshWords)
}

func (m *SEncodeManager) GetSeed(key string) uint32 {
	var h uint32 = 0x811c9dc5
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		// Math.imul のシミュレーション（32ビットオーバーフローを許容）
		h = h * 0x01000193
	}
	return h // >>> 0 はGoの uint32 で表現されます
}

func (m *SEncodeManager) CreateRng(seed uint32) func() float64 {
	s := seed
	return func() float64 {
		// | 0 のシミュレーション（int32へのキャストと等価ですが、シード管理はuint32で行います）
		s = (s*1664525 + 1013904223)
		return float64(s) / 4294967296.0
	}
}

func (m *SEncodeManager) GenerateSignature(data []byte) int {
	sig := m.MagicSalt
	for i := 0; i < len(data); i++ {
		// Math.imul(sig ^ data[i], 0x01000193) の再現
		imul := uint32(sig^int(data[i])) * 0x01000193
		sig = int(imul) & 0xFF
	}
	return sig
}

func (m *SEncodeManager) ApplyLogic(val, xor, salt, step int) int {
	mode := m.LogicSequence[step%len(m.LogicSequence)]
	switch mode {
	case 0:
		return (val ^ xor ^ salt) & 0xFF
	case 1:
		return (val + xor + salt) & 0xFF
	case 2:
		return ((val ^ salt) - xor) & 0xFF
	case 3:
		return ((val - salt) ^ xor) & 0xFF
	case 4:
		return (val ^ (xor + salt)) & 0xFF
	case 5:
		return (val ^ salt ^ step) & 0xFF
	default:
		return (val ^ xor) & 0xFF
	}
}

func (m *SEncodeManager) ReverseLogic(val, xor, salt, step int) int {
	mode := m.LogicSequence[step%len(m.LogicSequence)]
	switch mode {
	case 0:
		return (val ^ xor ^ salt) & 0xFF
	case 1:
		return (val - xor - salt) & 0xFF
	case 2:
		return ((val + xor) ^ salt) & 0xFF
	case 3:
		return ((val ^ xor) + salt) & 0xFF
	case 4:
		return (val ^ (xor + salt)) & 0xFF
	case 5:
		return (val ^ step ^ salt) & 0xFF
	default:
		return (val ^ xor) & 0xFF
	}
}

func EncodeSEncode(buffer []byte, secretKey string, separator ...int) (string, error) {
	sep := math.MaxInt32
	if len(separator) > 0 && separator[0] > 0 {
		sep = separator[0]
	}

	manager, err := NewSEncodeManager(secretKey)
	if err != nil {
		return "", err
	}

	if len(buffer) == 0 {
		return "", nil
	}

	sig := manager.GenerateSignature(buffer)
	dataWithSig := make([]byte, len(buffer)+1)
	copy(dataWithSig, buffer)
	dataWithSig[len(buffer)] = byte(sig)

	phantomRng := manager.CreateRng(uint32(manager.InitialXor ^ manager.MagicSalt))
	currentXor := manager.InitialXor
	rollingOffset := manager.MagicSalt
	var result strings.Builder

	tokenCount := 0
	hasMorphed := false

	nextPhantomStep := int(math.Floor(phantomRng()*16)) + 5
	totalProcessedSteps := 0

	for i := 0; i < len(dataWithSig); i++ {
		if !hasMorphed && tokenCount >= sep {
			manager.DynamicMorphTable(sep)
			hasMorphed = true
		}

		if phantomRng() < 0.25 {
			junkIdx := int(math.Floor(phantomRng() * float64(len(manager.JunkWords))))
			result.WriteString(manager.JunkWords[junkIdx])
			tokenCount++
		}

		for totalProcessedSteps >= nextPhantomStep {
			if !hasMorphed && tokenCount >= sep {
				manager.DynamicMorphTable(sep)
				hasMorphed = true
			}
			phantomVal := (currentXor ^ rollingOffset ^ totalProcessedSteps) & 0xFF
			hexKey := "x" + strconv.FormatInt(int64(phantomVal), 16)
			if len(hexKey) == 2 {
				hexKey = "x0" + hexKey[1:]
			}
			result.WriteString(manager.ConversionMap[hexKey])
			tokenCount++

			currentXor = (currentXor + phantomVal) & 0xFF
			nextPhantomStep += int(math.Floor(phantomRng()*16)) + 5
			totalProcessedSteps++
		}

		b := int(dataWithSig[i])
		rot := uint((manager.PoisonKey + totalProcessedSteps) % 8)
		// JavaScriptのビット演算シフトの再現
		rotated := ((b << rot) | (b >> (8 - rot))) & 0xFF
		obfuscated := manager.ApplyLogic(rotated, currentXor, rollingOffset, totalProcessedSteps)

		hexKey := "x" + strconv.FormatInt(int64(obfuscated), 16)
		if len(hexKey) == 2 {
			hexKey = "x0" + hexKey[1:]
		}
		result.WriteString(manager.ConversionMap[hexKey])
		tokenCount++

		currentXor = (currentXor + obfuscated + totalProcessedSteps) & 0xFF
		rollingOffset = (rollingOffset ^ b) & 0xFF
		totalProcessedSteps++
	}

	return result.String(), nil
}

func DecodeSEncode(text string, secretKey string, separator ...int) ([]byte, error) {
	sep := math.MaxInt32
	if len(separator) > 0 && separator[0] > 0 {
		sep = separator[0]
	}

	manager, err := NewSEncodeManager(secretKey)
	if err != nil {
		return nil, err
	}

	junkSet := make(map[string]bool)
	for _, w := range manager.JunkWords {
		junkSet[w] = true
	}

	failRng := manager.CreateRng(manager.GetSeed(secretKey + "_fail"))
	generateFakeBuffer := func(length int) []byte {
		if length <= 0 {
			length = 32
		}
		fake := make([]byte, length)
		for i := 0; i < length; i++ {
			fake[i] = byte(math.Floor(failRng() * 256))
		}
		return fake
	}

	sortedWords := make([]string, len(BaseWords))
	copy(sortedWords, BaseWords)
	sort.Slice(sortedWords, func(i, j int) bool {
		return len(sortedWords[i]) > len(sortedWords[j])
	})

	// 正規表現エスケープと結合
	var escapedKeys []string
	for _, v := range sortedWords {
		escapedKeys = append(escapedKeys, regexp.QuoteMeta(v))
	}
	re := regexp.MustCompile(strings.Join(escapedKeys, "|"))
	matches := re.FindAllString(text, -1)

	estimatedLen := int(math.Floor(float64(len(matches)) * 0.7))

	var resultBytes []int
	phantomRng := manager.CreateRng(uint32(manager.InitialXor ^ manager.MagicSalt))
	currentXor := manager.InitialXor
	rollingOffset := manager.MagicSalt

	nextPhantomStep := int(math.Floor(phantomRng()*16)) + 5
	totalProcessedSteps := 0
	mIdx := 0

	tokenCount := 0
	hasMorphed := false

	for mIdx < len(matches) {
		if !hasMorphed && tokenCount >= sep {
			manager.DynamicMorphTable(sep)
			junkSet = make(map[string]bool)
			for _, w := range manager.JunkWords {
				junkSet[w] = true
			}
			hasMorphed = true
		}

		if phantomRng() < 0.25 {
			phantomRng()
			if mIdx < len(matches) && junkSet[matches[mIdx]] {
				tokenCount++
				mIdx++
			}
		}

		for totalProcessedSteps >= nextPhantomStep && mIdx < len(matches) {
			if !hasMorphed && tokenCount >= sep {
				manager.DynamicMorphTable(sep)
				junkSet = make(map[string]bool)
				for _, w := range manager.JunkWords {
					junkSet[w] = true
				}
				hasMorphed = true
			}

			token := matches[mIdx]
			if junkSet[token] {
				tokenCount++
				mIdx++
				continue
			}

			obfuscated, exists := manager.ReverseMap[token]
			if exists {
				currentXor = (currentXor + obfuscated) & 0xFF
				nextPhantomStep += int(math.Floor(phantomRng()*16)) + 5
				totalProcessedSteps++
				tokenCount++
				mIdx++
			} else {
				return generateFakeBuffer(estimatedLen), nil
			}
		}

		if mIdx < len(matches) {
			token := matches[mIdx]
			if junkSet[token] {
				tokenCount++
				mIdx++
				continue
			}

			obfuscated, exists := manager.ReverseMap[token]
			if exists {
				rotated := manager.ReverseLogic(obfuscated, currentXor, rollingOffset, totalProcessedSteps)
				rot := uint((manager.PoisonKey + totalProcessedSteps) % 8)
				// JavaScriptの無符号右シフト・左シフトの再現
				originalByte := ((rotated >> rot) | (rotated << (8 - rot))) & 0xFF

				resultBytes = append(resultBytes, originalByte)

				currentXor = (currentXor + obfuscated + totalProcessedSteps) & 0xFF
				rollingOffset = (rollingOffset ^ originalByte) & 0xFF
				totalProcessedSteps++
				tokenCount++
				mIdx++
			} else {
				return generateFakeBuffer(estimatedLen), nil
			}
		}
	}

	if len(resultBytes) < 1 {
		return generateFakeBuffer(16), nil
	}

	receivedSig := resultBytes[len(resultBytes)-1]
	resultBytes = resultBytes[:len(resultBytes)-1]

	dataOnly := make([]byte, len(resultBytes))
	for i, v := range resultBytes {
		dataOnly[i] = byte(v)
	}

	calculatedSig := manager.GenerateSignature(dataOnly)

	if calculatedSig != receivedSig {
		return generateFakeBuffer(len(dataOnly)), nil
	}

	return dataOnly, nil
}

func RandomGenerate(length int, prefix ...string) string {
	p1 := "_"
	p2 := ""
	if len(prefix) > 0 {
		p1 = prefix[0]
	}
	if len(prefix) > 1 {
		p2 = prefix[1]
	}

	if len(BaseWords) == 0 {
		return ""
	}

	arr := make([]string, length)
	for i := 0; i < length; i++ {
		arr[i] = BaseWords[rand.Intn(len(BaseWords))]
	}

	specialIndex := -1
	if p2 != "" && length > 1 {
		specialIndex = rand.Intn(length - 1)
	}

	var result strings.Builder
	for i, word := range arr {
		if i == 0 {
			result.WriteString(word)
			continue
		}
		currentPrefix := p1
		if i-1 == specialIndex {
			currentPrefix = p2
		}
		result.WriteString(currentPrefix)
		result.WriteString(word)
	}

	return result.String()
}
