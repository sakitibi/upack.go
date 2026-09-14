package main

import (
	"fmt"
	"log"

	"github.com/sakitibi/upack.go/sencode"
)

func main() {
	// 受信者側の鍵ペアを生成
	recipientKeyPair, err := sencode.GenerateKeyPair()
	if err != nil {
		log.Fatalf("鍵ペアの生成に失敗しました: %v", err)
	}

	// --------------------------------------------------
	// 鍵のエクスポートとインポートのテスト
	// --------------------------------------------------
	fmt.Println("=== 鍵の入出力テスト ===")

	// PEM フォーマットのエクスポート
	pubPEM, err := sencode.ExportPublicKey(&recipientKeyPair.PublicKey)
	if err != nil {
		log.Fatalf("公開鍵(PEM)のエクスポート失敗: %v", err)
	}
	privPEM, err := sencode.ExportPrivateKey(recipientKeyPair)
	if err != nil {
		log.Fatalf("秘密鍵(PEM)のエクスポート失敗: %v", err)
	}

	fmt.Printf("公開鍵 (PEM):\n%s\n", pubPEM)
	fmt.Printf("秘密鍵 (PEM):\n%s\n", privPEM)

	// PEM フォーマットからのインポート
	importedPubKey, err := sencode.ImportPublicKey(pubPEM)
	if err != nil {
		log.Fatalf("公開鍵(PEM)のインポート失敗: %v", err)
	}
	importedPrivKey, err := sencode.ImportPrivateKey(privPEM)
	if err != nil {
		log.Fatalf("秘密鍵(PEM)のインポート失敗: %v", err)
	}

	// JWK フォーマットのテスト
	pubJWK, err := sencode.ExportPublicKeyJWK(&recipientKeyPair.PublicKey)
	if err != nil {
		log.Fatalf("公開鍵(JWK)のエクスポート失敗: %v", err)
	}
	privJWK, err := sencode.ExportPrivateKeyJWK(recipientKeyPair)
	if err != nil {
		log.Fatalf("秘密鍵(JWK)のエクスポート失敗: %v", err)
	}

	fmt.Printf("公開鍵 (JWK):\n%s\n\n", pubJWK)
	fmt.Printf("秘密鍵 (JWK):\n%s\n\n", privJWK)

	// JWK フォーマットからのインポート確認
	_, err = sencode.ImportPublicKeyJWK(pubJWK)
	if err != nil {
		log.Fatalf("公開鍵(JWK)のインポート失敗: %v", err)
	}
	_, err = sencode.ImportPrivateKeyJWK(privJWK)
	if err != nil {
		log.Fatalf("秘密鍵(JWK)のインポート失敗: %v", err)
	}

	// --------------------------------------------------
	// エンコード・デコードのテスト
	// --------------------------------------------------
	fmt.Println("=== エンコード・デコードテスト ===")
	originalText := "Hello, Go World! 12345"
	fmt.Printf("元の文字列: %s\n", originalText)
	fmt.Println("--------------------------------------------------")

	inputBytes := []byte(originalText)
	separator := 50

	// インポートした公開鍵を使用してエンコード
	encodedString, err := sencode.EncodeSEncode(inputBytes, importedPubKey, separator)
	if err != nil {
		log.Fatalf("エンコードに失敗しました: %v", err)
	}

	fmt.Printf("エンコード結果（単語の羅列）:\n%s\n", encodedString)
	fmt.Println("--------------------------------------------------")

	// インポートした秘密鍵を使用してデコード
	decodedInterface, err := sencode.DecodeSEncode(encodedString, importedPrivKey, true, separator)
	if err != nil {
		log.Fatalf("デコードに失敗しました: %v", err)
	}

	switch v := decodedInterface.(type) {
	case string:
		fmt.Printf("デコード結果: %s\n", v)
	case []byte:
		log.Fatalf("復号または署名検証に失敗しました（ダミーデータが返されました）: %x", v)
	default:
		log.Fatalf("想定外の型が返されました")
	}

	fmt.Println("--------------------------------------------------")

	// --------------------------------------------------
	// 不正な鍵での検証テスト
	// --------------------------------------------------
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
