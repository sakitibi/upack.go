package sencode

// パッケージ外部からアクセスできるように大文字で定義
var BaseWords []string
var baseWords_tmp1 []string

// パッケージロード時に自動実行される初期化関数
func init() {
	baseWords_tmp1 = append(baseWords1, baseWords2...)
	BaseWords = append(baseWords_tmp1, baseWords3...)
}
