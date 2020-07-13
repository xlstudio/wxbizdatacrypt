package wxbizdatacrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var errorCode = map[string]int{
	"illegalAppId":      -41000,
	"illegalAesKey":     -41001,
	"illegalIv":         -41002,
	"illegalBuffer":     -41003,
	"decodeBase64Error": -41004,
	"decodeJsonError":   -41005,
}

// WxBizDataCrypt represents an active WxBizDataCrypt object
type WxBizDataCrypt struct {
	AppId      string
	SessionKey string
}

type showError struct {
	errorCode int
	errorMsg  error
}

func (e showError) Error() string {
	return fmt.Sprintf("{code: %v, error: \"%v\"}", e.errorCode, e.errorMsg)
}

// Decrypt Weixin APP's AES Data
// If isJSON is true, Decrypt return JSON type.
// If isJSON is false, Decrypt return map type.
func (wxCrypt *WxBizDataCrypt) Decrypt(encryptedData string, iv string, isJSON bool) (interface{}, error) {
	sessionKey := strings.Replace(strings.TrimSpace(wxCrypt.SessionKey), " ", "+", -1)
	if len(sessionKey) != 24 {
		return nil, showError{errorCode["illegalAesKey"], errors.New("sessionKey length is error")}
	}
	aesKey, err := base64.StdEncoding.DecodeString(sessionKey)
	if err != nil {
		return nil, showError{errorCode["decodeBase64Error"], err}
	}
	iv = strings.Replace(strings.TrimSpace(iv), " ", "+", -1)
	if len(iv) != 24 {
		return nil, showError{errorCode["illegalIv"], errors.New("iv length is error")}
	}
	aesIv, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, showError{errorCode["decodeBase64Error"], err}
	}
	encryptedData = strings.Replace(strings.TrimSpace(encryptedData), " ", "+", -1)
	aesCipherText, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, showError{errorCode["decodeBase64Error"], err}
	}
	aesPlantText := make([]byte, len(aesCipherText))

	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, showError{errorCode["illegalBuffer"], err}
	}

	mode := cipher.NewCBCDecrypter(aesBlock, aesIv)
	mode.CryptBlocks(aesPlantText, aesCipherText)
	aesPlantText = PKCS7UnPadding(aesPlantText)

	var decrypted map[string]interface{}

	re := regexp.MustCompile(`[^\{]*(\{.*\})[^\}]*`)
	aesPlantText = []byte(re.ReplaceAllString(string(aesPlantText), "$1"))
	err = json.Unmarshal(aesPlantText, &decrypted)
	if err != nil {
		return nil, showError{errorCode["decodeJsonError"], err}
	}

	if decrypted["watermark"].(map[string]interface{})["appid"] != wxCrypt.AppId {
		return nil, showError{errorCode["illegalAppId"], errors.New("appId is not match")}
	}

	if isJSON {
		return string(aesPlantText), nil
	}

	return decrypted, nil
}

// PKCS7UnPadding return unpadding []Byte plantText
func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	if length > 0 {
		unPadding := int(plantText[length-1])
		return plantText[:(length - unPadding)]
	}
	return plantText
}
