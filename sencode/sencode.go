package sencode

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

const DefaultSeparator = math.MaxInt32

func rotateLeft8(b byte, rot int) byte {
	shift := rot % 8
	if shift == 0 {
		return b
	}
	return byte((int(b)<<shift | int(b)>>(8-shift)) & 0xFF)
}

func rotateRight8(b byte, rot int) byte {
	shift := rot % 8
	if shift == 0 {
		return b
	}
	return byte((int(b)>>shift | int(b)<<(8-shift)) & 0xFF)
}

// 鍵ペア生成ヘルパー（ECDH P-256）
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ==========================================
// エンコード / デコード処理
// ==========================================

// ECDH 共有鍵の導出
func deriveSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) (string, error) {
	ecdhPriv, err := priv.ECDH()
	if err != nil {
		return "", err
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return "", err
	}

	secret, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%064x", secret), nil
}

func EncodeSEncode(input any, recipientPubKey *ecdsa.PublicKey, separator int) (string, error) {
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
	sharedKeyHex, err := deriveSharedSecret(ephemeralPriv, recipientPubKey)
	if err != nil {
		return "", err
	}

	// 非圧縮形式の公開鍵 (65 bytes)
	ephemeralECDHPub, err := ephemeralPriv.PublicKey.ECDH()
	if err != nil {
		return "", err
	}
	exportedPubKey := ephemeralECDHPub.Bytes()

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

	sig := bodyManager.GenerateSignature(rawData)
	sigByte := sig[0] // 最初の1バイトを採用

	dataWithSig := make([]byte, len(rawData)+1)
	copy(dataWithSig, rawData)
	dataWithSig[len(rawData)] = sigByte

	phantomRng := bodyManager.CreateRng(uint32(bodyManager.InitialXor ^ bodyManager.MagicSalt))
	currentXor := bodyManager.InitialXor
	rollingOffset := bodyManager.MagicSalt

	nextPhantomStep := int(phantomRng()*16) + 5
	totalProcessedSteps := 0
	hasMorphed := false

	for i := range len(dataWithSig) {
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

		// 左回転処理を修正
		rotated := rotateLeft8(b, rot)
		obfuscated := bodyManager.ApplyLogic(int(rotated), currentXor, rollingOffset, totalProcessedSteps)

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

	ecdhPub, err := ecdh.P256().NewPublicKey(pubKeyBytes)
	if err != nil {
		return generateFakeBuffer(estimatedLen), nil
	}

	// ecdh.PublicKey のバイト列から ecdsa.PublicKey を構築
	pubBytes := ecdhPub.Bytes()
	xBytes := pubBytes[1:33]
	yBytes := pubBytes[33:65]
	ephemeralPubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	// 共通鍵の導出
	sharedKeyHex, err := deriveSharedSecret(recipientPrivKey, ephemeralPubKey)
	if err != nil {
		return generateFakeBuffer(estimatedLen), nil
	}

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
				rotated := bodyManager.ReverseLogic(obfuscated, currentXor, rollingOffset, totalProcessedSteps)
				rot := (bodyManager.PoisonKey + totalProcessedSteps) % 8

				// 右回転処理を修正
				originalByte := rotateRight8(byte(rotated), rot)

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

	const sigLen = 1
	if len(resultBytes) < sigLen {
		return generateFakeBuffer(1), nil
	}

	totalLen := len(resultBytes)
	dataOnly := resultBytes[:totalLen-sigLen]
	receivedSigByte := resultBytes[totalLen-sigLen]
	calculatedSig := bodyManager.GenerateSignature(dataOnly)

	// 1バイト署名の検証
	if calculatedSig[0] != receivedSigByte {
		return generateFakeBuffer(len(dataOnly)), nil
	}

	if textoutput {
		return string(dataOnly), nil
	}
	return dataOnly, nil
}
