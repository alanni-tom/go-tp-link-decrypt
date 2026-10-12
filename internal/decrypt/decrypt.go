// Package decrypt 移植自 C 版本的 libsecurity 逻辑，负责
// 从 TP-Link 固件中验证 RSA-PSS 签名、提取 AES 密钥并解密固件数据。
package decrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// tapoMagic 是 Tapo 固件中用于判断是否跳过解密的 magic 序列。
// 对应 C 中 rsa2_pss_sha256_verifysig 里的 magic[]。
var tapoMagic = []byte{
	0xaa, 0x55, 0x9d, 0xd1, 0xa8, 0xc8, 0x83, 0x31,
	0xc9, 0x69, 0xfb, 0xbf, 0xbc, 0xf0, 0xd4, 0x32,
	0x70, 0xc7, 0x55, 0xaa,
}

// Result 保存解密结果。
type Result struct {
	// Key 是从签名 salt 中提取的 AES 密钥（16 字节）。
	Key []byte
	// IV 是从签名 salt 中提取的 AES IV（16 字节）。
	IV []byte
	// Decrypted 保存解密后的完整固件缓冲区（签名区域已清零，解密区已解）。
	Decrypted []byte
}

// verifyPSS 精确还原 C 中 rsa2_pss_sha256_verifysig 的非标准逻辑。
//
// 该函数并不直接使用 rsa.VerifyPSS，而是手动进行 RSA 解密，再对结果
// 做 PSS 类似结构解析。sig 传入的是原始签名（内部会反转字节序），
// data 传入的是「签名区已清零后的固件数据」。返回 (salt, error)。
func verifyPSS(pub *rsa.PublicKey, sig []byte, data []byte, dataLen int) ([]byte, error) {
	bytesLen := (pub.N.BitLen() + 7) / 8
	hashLen := sha256.Size // 32

	// C 中 rsaVerifySign 会对签名反转字节序后再交给验签函数。
	sigRev := make([]byte, len(sig))
	for i := range sig {
		sigRev[i] = sig[len(sig)-1-i]
	}

	// RSA 解密：out = sig^e mod n，并按大端序转为字节。
	out := new(big.Int).Exp(new(big.Int).SetBytes(sigRev), big.NewInt(int64(pub.E)), pub.N)
	em := out.Bytes()
	// 补齐到 bytesLen，高位补零。
	if len(em) < bytesLen {
		pad := make([]byte, bytesLen-len(em))
		em = append(pad, em...)
	}

	// em[bytes-1] 应为 0xbc（非标准 PSS 结尾标记）。
	if em[bytesLen-1] != 0xbc {
		return nil, errors.New("RSA PSS Verify Error 1")
	}

	// MGF1 掩码：seed = em[bytesLen-1-hashLen : bytesLen-1]。
	mask := mgf1SHA256(em[bytesLen-1-hashLen:bytesLen-1], bytesLen-1-hashLen)
	// hash2 = em[bytesLen-1-hashLen : bytesLen-1]。
	hash2 := make([]byte, hashLen)
	copy(hash2, em[bytesLen-1-hashLen:bytesLen-1])

	// 逐字节对 mask 与 em 前置部分做异或，定位 salt 起始。
	var salt []byte
	saltPos := -1
	slen := 0
	for i := 0; i < bytesLen-1-hashLen; i++ {
		mask[i] ^= em[i]
		if i == 0 {
			mask[0] &= ^byte(0x80)
		}
		if saltPos <= 0 {
			if mask[i] == 0x01 {
				saltPos = i + 1
				salt = mask[saltPos:]
				slen = bytesLen - 1 - hashLen - saltPos
			} else if mask[i] != 0 {
				return nil, errors.New("RSA PSS Verify Error 2")
			}
		}
	}

	if salt == nil {
		return nil, errors.New("RSA PSS Verify Error 2")
	}

	// 重建 em：前 8 字节为 0，随后拼接 data 的 hash 与 salt。
	em = make([]byte, 8+slen+hashLen)
	copy(em[8+hashLen:], salt[:slen])
	h1 := sha256.Sum256(data[:dataLen])
	copy(em[8:], h1[:])
	h := sha256.Sum256(em)

	if !bytes.Equal(h[:], hash2) {
		return nil, errors.New("RSA PSS Verify Error 3")
	}

	return salt[:slen], nil
}

// mgf1SHA256 实现 MGF1 掩码生成（与 C 中 RSA_SHA256_MGF1 一致，计数器为 4 字节大端）。
func mgf1SHA256(seed []byte, maskLen int) []byte {
	mask := make([]byte, maskLen)
	rounds := (maskLen + 31) / 32
	for i := 0; i < rounds; i++ {
		var counter [4]byte
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)
		h := sha256.New()
		h.Write(seed)
		h.Write(counter[:])
		copy(mask[i*32:], h.Sum(nil))
	}
	return mask
}

// parsePublicKeyBlob 从 base64 的 MS PUBKEYBLOB 中解析出 RSA 公钥。
func parsePublicKeyBlob(b64 string) (*rsa.PublicKey, error) {
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	// 结构: 8 字节 PUBKEYSTRUC + RSAPUBKEY(magic 4, bitlen 4, pubexp 4) + modulus
	// 参考 rsaVerify.h 中 MY_PUBLICKEYSTRUC(8) + MY_RSAPUBKEY(12)。
	if len(blob) < 8+12 {
		return nil, errors.New("public key blob too short")
	}
	if string(blob[8:12]) != "RSA1" {
		return nil, errors.New("public key magic != RSA1")
	}
	bitlen := uint32(blob[12]) | uint32(blob[13])<<8 | uint32(blob[14])<<16 | uint32(blob[15])<<24
	pubexp := uint32(blob[16]) | uint32(blob[17])<<8 | uint32(blob[18])<<16 | uint32(blob[19])<<24

	// modulus 为小端序存储，需反转。C 中从偏移 20 起按 bitlen/8 字节取模数并反转。
	modBytes := blob[20:]
	nBytes := int(bitlen / 8)
	if nBytes > len(modBytes) {
		return nil, errors.New("modulus length exceeds blob")
	}
	modReversed := make([]byte, nBytes)
	for i := 0; i < nBytes; i++ {
		modReversed[i] = modBytes[nBytes-1-i]
	}
	n := new(big.Int).SetBytes(modReversed)

	return &rsa.PublicKey{N: n, E: int(pubexp)}, nil
}

// DecryptRSA 处理 fw-type / Tapo 固件：验签并解密数据。
//
//   - rawFw       完整固件缓冲区（用于输出和解密区域）。
//   - sigPos      签名在 rawFw 中的绝对偏移。
//   - sigLen      签名长度（256 字节）。
//   - fwDataPos   传给验签的数据起点绝对偏移。
//   - dataDecOffset 加密数据相对 fwDataPos 的偏移。
//   - keyB64      RSA 公钥（base64 MS PUBKEYBLOB）。
//
// 与 C 一致：解密前先把签名区清零（清零后区域计入验签 data），
// 解密长度为 (len(rawFw) - (fwDataPos+dataDecOffset)) & ~0xF。
func DecryptRSA(rawFw []byte, sigPos, sigLen, fwDataPos, dataDecOffset int, keyB64 string) (*Result, error) {
	pub, err := parsePublicKeyBlob(keyB64)
	if err != nil {
		return nil, err
	}
	if sigPos < 0 || sigPos+sigLen > len(rawFw) {
		return nil, errors.New("signature out of range")
	}

	// 复制完整缓冲区，并把签名区域清零。
	out := make([]byte, len(rawFw))
	copy(out, rawFw)
	clear(out[sigPos : sigPos+sigLen])

	// 签名从原始缓冲区读出。
	signature := rawFw[sigPos : sigPos+sigLen]

	// 验签数据使用清零签名后的缓冲区（对应 C 中 fw_buffer + fw_data_pos）。
	fwData := out[fwDataPos:]
	salt, err := verifyPSS(pub, signature, fwData, len(fwData))
	if err != nil {
		return nil, err
	}
	if len(salt) < 32 {
		return nil, errors.New("salt too short for AES key/iv")
	}

	// 前 16 字节为 KEY，后 16 字节为 IV。
	key := salt[:16]
	iv := salt[16:32]

	// Tapo 守卫：若 data+0x240 处的 magic 匹配则不解密（与 C 一致）。
	if len(fwData) >= 0x240+len(tapoMagic) && bytes.Equal(fwData[0x240:0x240+len(tapoMagic)], tapoMagic) {
		return &Result{Key: key, IV: iv, Decrypted: out}, nil
	}

	// 解密加密区。
	decryptStart := fwDataPos + dataDecOffset
	length := (len(out) - decryptStart) & ^(0xF)
	if length <= 0 || decryptStart+length > len(out) {
		return nil, errors.New("no encrypted data to decrypt")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 与 C 一致：在「签名区已清零」的缓冲区上原地解密。
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out[decryptStart:decryptStart+length], out[decryptStart:decryptStart+length])

	return &Result{Key: key, IV: iv, Decrypted: out}, nil
}

// DecryptDES 处理 Switch（Omada）固件：直接对整段固件做 DES-CBC 解密（无 RSA 验签）。
// keyHex 与 ivHex 为十六进制字符串（如 "0001020304050607"）。
func DecryptDES(rawFw []byte, keyHex, ivHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode DES key: %w", err)
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("decode DES iv: %w", err)
	}
	if len(key) != 8 || len(iv) != 8 {
		return nil, errors.New("DES key/iv must be 8 bytes")
	}

	out := make([]byte, len(rawFw))
	copy(out, rawFw)

	// 与 C 中 EVP_CIPHER_CTX_set_padding(ctx,0) 一致：无填充。
	length := len(rawFw) & ^7 // 对齐到 8 的倍数
	if length > 0 {
		block, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out[:length], rawFw[:length])
	}

	return out, nil
}
