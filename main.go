package main

import (
	"fmt"
	"log"

	"github.com/sakitibi/upack.go/sencode"
)

func main() {
	secretKey := "my-super-secret-key"
	originalText := "Hello, Go World! 12345"

	fmt.Printf("元の文字列: %s\n", originalText)
	fmt.Println("--------------------------------------------------")

	// 1. エンコード処理 (文字列 -> バイト列 -> 暗号化された単語列)
	inputBytes := []byte(originalText)
	encodedString, err := sencode.EncodeSEncode(inputBytes, secretKey, 0)
	if err != nil {
		log.Fatalf("エンコードに失敗しました: %v", err)
	}

	fmt.Printf("エンコード結果（単語の羅列）:\n%s\n", encodedString)
	fmt.Println("--------------------------------------------------")

	// 2. デコード処理 (単語列 -> バイト列 -> 元の文字列)
	// 第3引数を true にしているので interface{} として返ってくる中身は string
	decodedInterface, err := sencode.DecodeSEncode(encodedString, secretKey, true, 0)
	if err != nil {
		log.Fatalf("デコードに失敗しました: %v", err)
	}

	// 型アサーションで string を取り出す
	decodedText, ok := decodedInterface.(string)
	if !ok {
		log.Fatalf("デコード結果の型アサーション(string)に失敗しました")
	}

	fmt.Printf("デコード結果: %s\n", decodedText)
	fmt.Println("--------------------------------------------------")

	// 3. 検証（間違った鍵を入れた場合の挙動テスト）
	wrongKey := "wrong-key"
	// 第3引数を false にしているので interface{} として返ってくる中身は []byte
	fakeInterface, err := sencode.DecodeSEncode(encodedString, wrongKey, false, 0)
	if err != nil {
		// エラーが出た場合は安全に処理を逃がす
		fmt.Printf("間違った鍵でのデコードに失敗しました（期待通りの挙動）: %v\n", err)
	} else {
		// 型アサーションで []byte を取り出す
		fakeBytes, ok := fakeInterface.([]byte)
		if !ok {
			log.Fatalf("偽データの型アサーション([]byte)に失敗しました")
		}

		// エラーがなかった場合のみ、長さを考慮して出力
		end := 10
		if len(fakeBytes) < end {
			end = len(fakeBytes)
		}
		fmt.Printf("間違った鍵でのデコード結果(偽のランダムデータ): %x...\n", fakeBytes[:end])
	}
}
