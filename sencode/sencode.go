package sencode

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

const DefaultSeparator = math.MaxInt32

// 鍵ペア生成ヘルパー（ECDH P-256）
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ==========================================
// エンコード / デコード処理
// ==========================================

// ECDH 共有鍵の導出
func deriveSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) string {
	x, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return fmt.Sprintf("%064x", x)
}

func EncodeSEncode(input interface{}, recipientPubKey *ecdsa.PublicKey, separator int) (string, error) {
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

	ephemeralPriv, err := GenerateKeyPair()
	if err != nil {
		return "", err
	}
	sharedKeyHex := deriveSharedSecret(ephemeralPriv, recipientPubKey)

	// 非圧縮形式の公開鍵 (65 bytes)
	exportedPubKey := elliptic.Marshal(elliptic.P256(), ephemeralPriv.PublicKey.X, ephemeralPriv.PublicKey.Y)

	// ヘッダー構造: [1byte: 公開鍵長(65)][65bytes: 非圧縮公開鍵]
	headerPayload := make([]byte, 1+len(exportedPubKey))
	headerPayload[0] = byte(len(exportedPubKey))
	copy(headerPayload[1:], exportedPubKey)

	headerManager := NewSEncodeManager("ephemeral_header_key", nil)
	if err := headerManager.Initialize(); err != nil {
		return "", err
	}

	var result strings.Builder
	tokenCount := 0

	for _, b := range headerPayload {
		hexKey := fmt.Sprintf("x%02x", b)
		result.WriteString(headerManager.ConversionMap[hexKey])
		tokenCount++
	}

	bodyManager := NewSEncodeManager(sharedKeyHex, nil)
	if err := bodyManager.Initialize(); err != nil {
		return "", err
	}

	// 署名 (16 bytes) を計算してデータの末尾に追加
	sig := bodyManager.GenerateSignature(rawData)
	dataWithSig := make([]byte, len(rawData)+len(sig))
	copy(dataWithSig, rawData)
	copy(dataWithSig[len(rawData):], sig)

	phantomRng := bodyManager.CreateRng(uint32(bodyManager.InitialXor ^ bodyManager.MagicSalt))
	currentXor := bodyManager.InitialXor
	rollingOffset := bodyManager.MagicSalt

	nextPhantomStep := int(phantomRng()*16) + 5
	totalProcessedSteps := 0
	hasMorphed := false

	for i := 0; i < len(dataWithSig); i++ {
		if !hasMorphed && tokenCount >= separator {
			if err := bodyManager.DynamicMorphTable(separator); err != nil {
				return "", err
			}
			hasMorphed = true
		}

		if phantomRng() < 0.25 {
			junkIdx := int(phantomRng() * float64(len(bodyManager.JunkWords)))
			result.WriteString(bodyManager.JunkWords[junkIdx])
			tokenCount++
		}

		for totalProcessedSteps >= nextPhantomStep {
			if !hasMorphed && tokenCount >= separator {
				if err := bodyManager.DynamicMorphTable(separator); err != nil {
					return "", err
				}
				hasMorphed = true
			}
			phantomVal := (currentXor ^ rollingOffset ^ totalProcessedSteps) & 0xFF
			hexKey := fmt.Sprintf("x%02x", phantomVal&0xFF)
			result.WriteString(bodyManager.ConversionMap[hexKey])
			tokenCount++

			currentXor = (currentXor + phantomVal) & 0xFF
			nextPhantomStep += int(phantomRng()*16) + 5
			totalProcessedSteps++
		}

		b := dataWithSig[i]
		rot := (bodyManager.PoisonKey + totalProcessedSteps) % 8
		rotated := ((int(b) << rot) | (int(b) >> (8 - rot))) & 0xFF
		obfuscated := bodyManager.ApplyLogic(rotated, currentXor, rollingOffset, totalProcessedSteps)

		hexKey := fmt.Sprintf("x%02x", obfuscated&0xFF)
		result.WriteString(bodyManager.ConversionMap[hexKey])
		tokenCount++

		currentXor = (currentXor + int(obfuscated) + totalProcessedSteps) & 0xFF
		rollingOffset = (rollingOffset ^ int(b)) & 0xFF
		totalProcessedSteps++
	}

	return result.String(), nil
}

func DecodeSEncode(text string, recipientPrivKey *ecdsa.PrivateKey, textoutput bool, separator int) (interface{}, error) {
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

	estimatedLen := int(float64(len(matches)) * 0.7)
	generateFakeBuffer := func(length int) []byte {
		if length <= 0 {
			length = 32
		}
		fake := make([]byte, length)
		_, _ = rand.Read(fake)
		return fake
	}

	if len(matches) < 66 {
		return generateFakeBuffer(estimatedLen), nil
	}

	headerManager := NewSEncodeManager("ephemeral_header_key", nil)
	if err := headerManager.Initialize(); err != nil {
		return nil, err
	}

	pubKeyLenWord := matches[0]
	pubKeyLen, ok := headerManager.ReverseMap[pubKeyLenWord]
	if !ok || pubKeyLen != 65 {
		return generateFakeBuffer(estimatedLen), nil
	}

	pubKeyBytes := make([]byte, pubKeyLen)
	for i := 0; i < pubKeyLen; i++ {
		val, ok := headerManager.ReverseMap[matches[1+i]]
		if !ok {
			return generateFakeBuffer(estimatedLen), nil
		}
		pubKeyBytes[i] = byte(val)
	}

	// P-256 公開鍵を復元
	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil || y == nil {
		return generateFakeBuffer(estimatedLen), nil
	}
	ephemeralPubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// 共通鍵の導出
	sharedKeyHex := deriveSharedSecret(recipientPrivKey, ephemeralPubKey)

	bodyManager := NewSEncodeManager(sharedKeyHex, nil)
	if err := bodyManager.Initialize(); err != nil {
		return nil, err
	}

	junkSet := make(map[string]bool)
	for _, jw := range bodyManager.JunkWords {
		junkSet[jw] = true
	}

	phantomRng := bodyManager.CreateRng(uint32(bodyManager.InitialXor ^ bodyManager.MagicSalt))
	currentXor := bodyManager.InitialXor
	rollingOffset := bodyManager.MagicSalt

	nextPhantomStep := int(phantomRng()*16) + 5
	totalProcessedSteps := 0

	mIdx := 1 + pubKeyLen
	tokenCount := 1 + pubKeyLen
	hasMorphed := false

	var resultBytes []byte

	if tokenCount >= separator {
		if err := bodyManager.DynamicMorphTable(separator); err != nil {
			return nil, err
		}
		junkSet = make(map[string]bool)
		for _, jw := range bodyManager.JunkWords {
			junkSet[jw] = true
		}
		hasMorphed = true
	}

	for mIdx < len(matches) {
		if !hasMorphed && tokenCount >= separator {
			if err := bodyManager.DynamicMorphTable(separator); err != nil {
				return nil, err
			}
			junkSet = make(map[string]bool)
			for _, jw := range bodyManager.JunkWords {
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
				if err := bodyManager.DynamicMorphTable(separator); err != nil {
					return nil, err
				}
				junkSet = make(map[string]bool)
				for _, jw := range bodyManager.JunkWords {
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

			if obfuscated, ok := bodyManager.ReverseMap[token]; ok {
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

			if obfuscated, ok := bodyManager.ReverseMap[token]; ok {
				rotated := int(bodyManager.ReverseLogic(obfuscated, currentXor, rollingOffset, totalProcessedSteps))
				rot := (bodyManager.PoisonKey + totalProcessedSteps) % 8

				originalByte := byte(((rotated >> rot) | (rotated << (8 - rot))) & 0xFF)

				resultBytes = append(resultBytes, originalByte)

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

	const sigLen = 16
	if len(resultBytes) < sigLen {
		return generateFakeBuffer(16), nil
	}

	totalLen := len(resultBytes)
	dataOnly := resultBytes[:totalLen-sigLen]
	receivedSig := resultBytes[totalLen-sigLen:]
	calculatedSig := bodyManager.GenerateSignature(dataOnly)

	// 署名検証 (16 bytes)
	if !bytes.Equal(calculatedSig, receivedSig) {
		return generateFakeBuffer(len(dataOnly)), nil
	}

	if textoutput {
		return string(dataOnly), nil
	}
	return dataOnly, nil
}
