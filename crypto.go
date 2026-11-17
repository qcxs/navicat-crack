package main

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"sync"
)

// referencePublicKey 是 Navicat 内嵌的 392 字符 RSA 公钥（SPKI Base64）。
// 将其下标 364 的 'S' 改为 'T' 后，模数变为 N' = N + 2^122 = 47 * q，可分解。
const referencePublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I" +
	"qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv" +
	"a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF" +
	"R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2" +
	"WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt" +
	"YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ" +
	"awIDAQAB"

const publicKeyIndex = 364

var (
	cryptoOnce      sync.Once
	cryptoErr       error
	patchedModulus  *big.Int
	privateExponent *big.Int
	publicExponent  = big.NewInt(65537)
	blockSize       = 256
)

func initCrypto() error {
	cryptoOnce.Do(func() {
		cryptoErr = buildCrypto()
	})
	return cryptoErr
}

func buildCrypto() error {
	if len(referencePublicKey) != 392 || referencePublicKey[publicKeyIndex] != 'S' {
		return fmt.Errorf("内置公钥常量异常")
	}
	original, err := parseRSAPublicKey(referencePublicKey)
	if err != nil {
		return fmt.Errorf("解析原始公钥失败：%w", err)
	}
	patchedText := referencePublicKey[:publicKeyIndex] + "T" + referencePublicKey[publicKeyIndex+1:]
	patched, err := parseRSAPublicKey(patchedText)
	if err != nil {
		return fmt.Errorf("解析修改后公钥失败：%w", err)
	}

	delta := new(big.Int).Sub(patched.N, original.N)
	if delta.Cmp(new(big.Int).Lsh(big.NewInt(1), 122)) != 0 {
		return fmt.Errorf("公钥模数差值不是 2^122")
	}
	if new(big.Int).Mod(patched.N, big.NewInt(47)).Sign() != 0 {
		return fmt.Errorf("修改后的模数不是 47 的倍数")
	}
	q := new(big.Int).Quo(patched.N, big.NewInt(47))
	if !q.ProbablyPrime(16) {
		return fmt.Errorf("修改后的模数分解结果不是素数")
	}
	phi := new(big.Int).Mul(big.NewInt(46), new(big.Int).Sub(q, big.NewInt(1)))
	d := new(big.Int).ModInverse(publicExponent, phi)
	if d == nil {
		return fmt.Errorf("无法计算私有指数")
	}
	patchedModulus = patched.N
	privateExponent = d
	blockSize = (patched.N.BitLen() + 7) / 8
	return nil
}

func parseRSAPublicKey(text string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("不是 RSA 公钥")
	}
	return rsaPub, nil
}

// decryptRequest 用 N'/D 解开离线激活请求码，返回 Type-2 填充后的 JSON 明文。
func decryptRequest(code string) ([]byte, error) {
	if err := initCrypto(); err != nil {
		return nil, err
	}
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, code)
	raw, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("请求码不是有效的 Base64：%w", err)
	}
	if len(raw) != blockSize {
		return nil, fmt.Errorf("请求码解码后为 %d 字节，应为 %d 字节", len(raw), blockSize)
	}
	c := new(big.Int).SetBytes(raw)
	if c.Cmp(patchedModulus) >= 0 {
		return nil, fmt.Errorf("请求码与当前密钥不匹配")
	}
	em := new(big.Int).Exp(c, privateExponent, patchedModulus).FillBytes(make([]byte, blockSize))
	if em[0] != 0 || em[1] != 2 {
		return nil, fmt.Errorf("请求码填充无效（请确认已应用补丁并重启 Navicat）")
	}
	sep := bytes.IndexByte(em[2:], 0)
	if sep < 0 {
		return nil, fmt.Errorf("请求码填充无效")
	}
	sep += 2
	if sep < 10 {
		return nil, fmt.Errorf("请求码填充长度异常")
	}
	for _, b := range em[2:sep] {
		if b == 0 {
			return nil, fmt.Errorf("请求码填充包含零字节")
		}
	}
	payload := em[sep+1:]
	if len(payload) == 0 {
		return nil, fmt.Errorf("请求码内容为空")
	}
	return payload, nil
}

// signActivation 用 N'/D 做 PKCS#1 v1.5 Type-1 私钥运算，返回激活码。
func signActivation(payload []byte) (string, error) {
	if err := initCrypto(); err != nil {
		return "", err
	}
	if len(payload) > blockSize-11 {
		return "", fmt.Errorf("注册信息过长（%d 字节，最多 %d 字节）", len(payload), blockSize-11)
	}
	em := make([]byte, blockSize)
	em[0] = 0
	em[1] = 1
	ps := blockSize - len(payload) - 3
	for i := 0; i < ps; i++ {
		em[2+i] = 0xFF
	}
	em[2+ps] = 0
	copy(em[3+ps:], payload)

	sig := new(big.Int).Exp(new(big.Int).SetBytes(em), privateExponent, patchedModulus)
	out := sig.FillBytes(make([]byte, blockSize))

	check := new(big.Int).Exp(sig, publicExponent, patchedModulus).FillBytes(make([]byte, blockSize))
	if !bytes.Equal(check, em) {
		return "", fmt.Errorf("激活码公钥回验失败")
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

// ---- 离线激活密钥（16 位短序列号）生成 ----

// 序列号使用 DES-ECB，密钥即 libcc.dll 中的数据：
// E9 7F B0 60 77 45 90 AE
var serialDESKey = []byte{0xE9, 0x7F, 0xB0, 0x60, 0x77, 0x45, 0x90, 0xAE}

// encodeSerial 将 3 字节随机前缀编码为 16 位序列号。
// 明文结构：随机 3 字节 + CE 32 65 20 FF（P=3、E=false、V=18、Ctype=2）。
func encodeSerial(prefix [3]byte) string {
	block, err := des.NewCipher(serialDESKey)
	if err != nil {
		return ""
	}
	plain := []byte{prefix[0], prefix[1], prefix[2], 0xCE, 0x32, 0x65, 0x20, 0xFF}
	encrypted := make([]byte, 8)
	block.Encrypt(encrypted, plain)

	raw := make([]byte, 10)
	raw[0] = 0x68
	raw[1] = 0x2A
	copy(raw[2:], encrypted)
	return base32.StdEncoding.EncodeToString(raw)
}

// generateOfflineKey 生成并自检一个新的离线激活密钥。
func generateOfflineKey() (string, error) {
	var prefix [3]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return "", fmt.Errorf("生成随机数失败：%w", err)
	}
	for i := 0; i < 8; i++ {
		key := encodeSerial(prefix)
		if validateOfflineKey(key) {
			return key, nil
		}
		if _, err := rand.Read(prefix[:]); err != nil {
			return "", fmt.Errorf("生成随机数失败：%w", err)
		}
	}
	return "", fmt.Errorf("生成的密钥未通过自检")
}

// validateOfflineKey 按短序列号规则校验密钥（Base32 -> 68 2A -> DES 解密）。
func validateOfflineKey(key string) bool {
	clean := strings.ToUpper(strings.TrimSpace(key))
	raw, err := base32.StdEncoding.DecodeString(clean)
	if err != nil || len(raw) != 10 || raw[0] != 0x68 || raw[1] != 0x2A {
		return false
	}
	block, err := des.NewCipher(serialDESKey)
	if err != nil {
		return false
	}
	plain := make([]byte, 8)
	block.Decrypt(plain, raw[2:])
	return plain[3] == 0xCE && plain[4] == 0x32 && plain[5] == 0x65 &&
		plain[6] == 0x20 && plain[7] == 0xFF
}
