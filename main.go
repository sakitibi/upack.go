package main

import (
	"fmt"
	"log"

	"github.com/sakitibi/upack.go/sencode"
)

func main() {
	// 1. 受信者側の鍵ペアを生成
	recipientKeyPair, err := sencode.GenerateKeyPair()
	if err != nil {
		log.Fatalf("鍵ペアの生成に失敗しました: %v", err)
	}

	originalText := "Hello, Go World! 12345"

	fmt.Printf("元の文字列: %s\n", originalText)
	fmt.Println("--------------------------------------------------")

	inputBytes := []byte(originalText)
	separator := 50

	encodedString, err := sencode.EncodeSEncode(inputBytes, &recipientKeyPair.PublicKey, separator)
	if err != nil {
		log.Fatalf("エンコードに失敗しました: %v", err)
	}

	fmt.Printf("エンコード結果（単語の羅列）:\n%s\n", encodedString)
	fmt.Println("--------------------------------------------------")

	decodedInterface, err := sencode.DecodeSEncode(encodedString, recipientKeyPair, true, separator)
	if err != nil {
		log.Fatalf("デコードに失敗しました: %v", err)
	}

	// 型アサーションで結果を確認
	switch v := decodedInterface.(type) {
	case string:
		fmt.Printf("デコード結果: %s\n", v)
	case []byte:
		// 署名検証失敗時などは []byte のダミーバッファが返る
		log.Fatalf("復号または署名検証に失敗しました（ダミーデータが返されました）: %x", v)
	default:
		log.Fatalf("想定外の型が返されました")
	}

	fmt.Println("--------------------------------------------------")

	wrongKeyPair, err := sencode.GenerateKeyPair()
	if err != nil {
		log.Fatalf("偽の鍵ペア生成に失敗しました: %v", err)
	}

	fakeInterface, err := sencode.DecodeSEncode(encodedString, wrongKeyPair, false, separator)
	if err != nil {
		fmt.Printf("間違った鍵でのデコード処理エラー: %v\n", err)
	} else {
		fakeBytes, ok := fakeInterface.([]byte)
		if !ok {
			log.Fatalf("偽データの型アサーション([]byte)に失敗しました")
		}

		end := 10
		if len(fakeBytes) < end {
			end = len(fakeBytes)
		}
		fmt.Printf("間違った鍵でのデコード結果(偽のランダムデータ): %x...\n", fakeBytes[:end])
	}
}
