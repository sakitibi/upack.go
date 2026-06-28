package sencode

import (
	"crypto/rand"
	"fmt"
	"math"
	mathrand "math/rand"
	"regexp"
	"sort"
	"strings"
)

const DefaultSeparator = math.MaxInt32

func EncodeSEncode(input interface{}, secretKey string, separator int) (string, error) {
	if separator <= 0 {
		separator = DefaultSeparator
	}

	var rawData []byte
	switch v := input.(type) {
	case string:
		rawData = []byte(v)
	case []byte:
		rawData = v
	default:
		return "", fmt.Errorf("invalid input type")
	}

	if len(rawData) == 0 {
		return "", nil
	}

	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		for i := 0; i < 8; i++ {
			iv[i] = byte(mathrand.Intn(256))
		}
	}

	dummyIv := make([]byte, 8)
	manager := NewSEncodeManager(secretKey, dummyIv)
	if err := manager.Initialize(); err != nil {
		return "", err
	}

	sig := manager.GenerateSignature(rawData)
	dataWithPayload := make([]byte, len(iv)+len(rawData)+len(sig))
	copy(dataWithPayload[0:8], iv)
	copy(dataWithPayload[8:8+len(rawData)], rawData)
	copy(dataWithPayload[8+len(rawData):], sig)

	phantomRng := manager.CreateRng(uint32(manager.InitialXor ^ manager.MagicSalt))
	currentXor := manager.InitialXor
	rollingOffset := manager.MagicSalt
	var result strings.Builder

	tokenCount := 0
	hasMorphed := false
	nextPhantomStep := int(phantomRng()*16) + 5
	totalProcessedSteps := 0
	ivSwapped := false

	for i := 0; i < len(dataWithPayload); i++ {
		if !ivSwapped && i == 8 {
			manager = NewSEncodeManager(secretKey, iv)
			if err := manager.Initialize(); err != nil {
				return "", err
			}

			phantomRng = manager.CreateRng(uint32(manager.InitialXor ^ manager.MagicSalt))
			currentXor = manager.InitialXor
			rollingOffset = manager.MagicSalt
			nextPhantomStep = int(phantomRng()*16) + 5

			totalProcessedSteps = 0
			if tokenCount >= separator {
				if err := manager.DynamicMorphTable(separator); err != nil {
					return "", err
				}
				hasMorphed = true
			} else {
				hasMorphed = false
			}
			ivSwapped = true
		}

		if !hasMorphed && tokenCount >= separator {
			if err := manager.DynamicMorphTable(separator); err != nil {
				return "", err
			}
			hasMorphed = true
		}

		if phantomRng() < 0.25 {
			junkIdx := int(phantomRng() * float64(len(manager.JunkWords)))
			result.WriteString(manager.JunkWords[junkIdx])
			tokenCount++
		}

		for totalProcessedSteps >= nextPhantomStep {
			if !hasMorphed && tokenCount >= separator {
				if err := manager.DynamicMorphTable(separator); err != nil {
					return "", err
				}
				hasMorphed = true
			}
			phantomVal := (currentXor ^ rollingOffset ^ totalProcessedSteps) & 0xFF
			hexKey := fmt.Sprintf("x%02x", phantomVal&0xFF)
			result.WriteString(manager.ConversionMap[hexKey])
			tokenCount++

			currentXor = (currentXor + phantomVal) & 0xFF
			nextPhantomStep += int(phantomRng()*16) + 5
			totalProcessedSteps++
		}

		b := dataWithPayload[i]
		rot := (manager.PoisonKey + totalProcessedSteps) % 8

		rotated := ((int(b) << rot) | (int(b) >> (8 - rot))) & 0xFF
		obfuscated := manager.ApplyLogic(rotated, currentXor, rollingOffset, totalProcessedSteps)

		hexKey := fmt.Sprintf("x%02x", obfuscated&0xFF)
		result.WriteString(manager.ConversionMap[hexKey])
		tokenCount++

		currentXor = (currentXor + int(obfuscated) + totalProcessedSteps) & 0xFF
		rollingOffset = (rollingOffset ^ int(b)) & 0xFF
		totalProcessedSteps++
	}

	return result.String(), nil
}

func DecodeSEncode(text string, secretKey string, textoutput bool, separator int) (interface{}, error) {
	if separator <= 0 {
		separator = DefaultSeparator
	}

	sortedWords := make([]string, len(BaseWords))
	copy(sortedWords, BaseWords)
	sort.Slice(sortedWords, func(i, j int) bool {
		return len(sortedWords[i]) > len(sortedWords[j])
	})

	escapedKeys := make([]string, len(sortedWords))
	for i, w := range sortedWords {
		escapedKeys[i] = regexp.QuoteMeta(w)
	}
	re := regexp.MustCompile(strings.Join(escapedKeys, "|"))
	matches := re.FindAllString(text, -1)
	if matches == nil {
		matches = []string{}
	}

	estimatedLen := int(float64(len(matches)) * 0.7)

	generateFakeBuffer := func(length int) []byte {
		if length <= 0 {
			length = 32
		}
		fake := make([]byte, length)
		_, _ = rand.Read(fake)
		return fake
	}

	dummyIv := make([]byte, 8)
	manager := NewSEncodeManager(secretKey, dummyIv)
	if err := manager.Initialize(); err != nil {
		return nil, err
	}

	junkSet := make(map[string]bool)
	for _, jw := range manager.JunkWords {
		junkSet[jw] = true
	}

	phantomRng := manager.CreateRng(uint32(manager.InitialXor ^ manager.MagicSalt))
	currentXor := manager.InitialXor
	rollingOffset := manager.MagicSalt

	nextPhantomStep := int(phantomRng()*16) + 5
	totalProcessedSteps := 0
	tokenCount := 0
	hasMorphed := false

	var resultBytes []byte
	mIdx := 0
	decodedBytesCount := 0
	ivSwapped := false

	for mIdx < len(matches) {
		if !ivSwapped && decodedBytesCount == 8 {
			realIv := resultBytes[0:8]
			manager = NewSEncodeManager(secretKey, realIv)
			if err := manager.Initialize(); err != nil {
				return nil, err
			}

			junkSet = make(map[string]bool)
			for _, jw := range manager.JunkWords {
				junkSet[jw] = true
			}

			phantomRng = manager.CreateRng(uint32(manager.InitialXor ^ manager.MagicSalt))
			currentXor = manager.InitialXor
			rollingOffset = manager.MagicSalt
			nextPhantomStep = int(phantomRng()*16) + 5

			totalProcessedSteps = 0
			if tokenCount >= separator {
				if err := manager.DynamicMorphTable(separator); err != nil {
					return nil, err
				}
				junkSet = make(map[string]bool)
				for _, jw := range manager.JunkWords {
					junkSet[jw] = true
				}
				hasMorphed = true
			} else {
				hasMorphed = false
			}
			ivSwapped = true
		}

		if !hasMorphed && tokenCount >= separator {
			if err := manager.DynamicMorphTable(separator); err != nil {
				return nil, err
			}
			junkSet = make(map[string]bool)
			for _, jw := range manager.JunkWords {
				junkSet[jw] = true
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
			if !hasMorphed && tokenCount >= separator {
				if err := manager.DynamicMorphTable(separator); err != nil {
					return nil, err
				}
				junkSet = make(map[string]bool)
				for _, jw := range manager.JunkWords {
					junkSet[jw] = true
				}
				hasMorphed = true
			}

			token := matches[mIdx]
			if junkSet[token] {
				tokenCount++
				mIdx++
				continue
			}

			if obfuscated, ok := manager.ReverseMap[token]; ok {
				currentXor = (currentXor + obfuscated) & 0xFF
				nextPhantomStep += int(phantomRng()*16) + 5
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

			if obfuscated, ok := manager.ReverseMap[token]; ok {
				rotated := int(manager.ReverseLogic(obfuscated, currentXor, rollingOffset, totalProcessedSteps))
				rot := (manager.PoisonKey + totalProcessedSteps) % 8

				originalByte := byte(((rotated >> rot) | (rotated << (8 - rot))) & 0xFF)

				resultBytes = append(resultBytes, originalByte)
				decodedBytesCount++

				currentXor = (currentXor + obfuscated + totalProcessedSteps) & 0xFF
				rollingOffset = (rollingOffset ^ int(originalByte)) & 0xFF
				totalProcessedSteps++
				tokenCount++
				mIdx++
			} else {
				return generateFakeBuffer(estimatedLen), nil
			}
		}
	}

	if len(resultBytes) < 25 {
		return generateFakeBuffer(16), nil
	}

	totalLen := len(resultBytes)
	dataOnly := resultBytes[8 : totalLen-16]
	receivedSig := resultBytes[totalLen-16:]
	calculatedSig := manager.GenerateSignature(dataOnly)

	isMatch := true
	for i := 0; i < 16; i++ {
		if calculatedSig[i] != receivedSig[i] {
			isMatch = false
		}
	}

	if !isMatch {
		return generateFakeBuffer(len(dataOnly)), nil
	}

	if textoutput {
		return string(dataOnly), nil
	}
	return dataOnly, nil
}

func RandomGenerate(length int, prefix, prefix2 string) string {
	if prefix == "" {
		prefix = "_"
	}
	if len(BaseWords) == 0 {
		return ""
	}

	arr := make([]string, length)
	for i := 0; i < length; i++ {
		arr[i] = BaseWords[mathrand.Intn(len(BaseWords))]
	}

	specialIndex := -1
	if prefix2 != "" && length > 1 {
		specialIndex = mathrand.Intn(length - 1)
	}

	var result strings.Builder
	for i, word := range arr {
		if i == 0 {
			result.WriteString(word)
			continue
		}
		currentPrefix := prefix
		if i-1 == specialIndex {
			currentPrefix = prefix2
		}
		result.WriteString(currentPrefix)
		result.WriteString(word)
	}

	return result.String()
}
