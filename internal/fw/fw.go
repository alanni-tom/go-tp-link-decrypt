// Package fw 检测 TP-Link 固件类型并给出相应的解密参数。
package fw

import (
	"bytes"
	"fmt"
)

// 固件类型常量，与 C 中 detect_firmware_ver 的返回值对应。
const (
	TypeUnknown = iota // 0: Switch / 其他（走 DES）
	TypeFWType         // 1: "fw-type:" 路由器/AP
	TypeTapo           // 2: Tapo/IPC 摄像头
)

const (
	fwTypeOffset = 0x14
	fwTypeString = "fw-type:"
	fwTypeLen    = 8

	tapoHeaderOffset = 6
)

// tapoFwHeader 是 Tapo/IPC 固件头 signature。
var tapoFwHeader = []byte{
	0x4c, 0x5e, 0x83, 0x1f, 0x53, 0x4b, 0xa1, 0xf8,
	0xf7, 0xc9, 0x18, 0xdf, 0x8f, 0xbf, 0x7d, 0xa1,
}

// Config 描述一种固件类型的解密参数。
type Config struct {
	Type          int
	FWDataPos     int // 传给验签的数据起点绝对偏移（fw_data_pos）
	SigPos        int // 签名绝对偏移（sig_pos）
	RSAVerPos     int // RSA 版本字段绝对偏移（RSA_VER_pos）
	DataDecOffset int // 加密数据相对 fw_data_pos 的偏移（data_dec_offset）
	RSAKey        string
}

// Detect 检测固件类型，返回对应 Config。
// 若为 Switch（type 0），RSAKey 为空，走 DES 分支。
func Detect(rawFw []byte) (Config, error) {
	if len(rawFw) >= fwTypeOffset+fwTypeLen &&
		bytes.Equal(rawFw[fwTypeOffset:fwTypeOffset+fwTypeLen], []byte(fwTypeString)) {
		fmt.Println(fwTypeString, "found")
		return Config{
			Type:          TypeFWType,
			FWDataPos:     0x14,
			SigPos:        0x130,
			RSAVerPos:     0x110,
			DataDecOffset: 0x130 - 0x14,
		}, nil
	}

	if len(rawFw) >= tapoHeaderOffset+len(tapoFwHeader) &&
		bytes.Equal(rawFw[tapoHeaderOffset:tapoHeaderOffset+len(tapoFwHeader)], tapoFwHeader) {
		fmt.Println("Tapo firmware header found")
		return Config{
			Type:          TypeTapo,
			FWDataPos:     0x00,
			SigPos:        0x20,
			RSAVerPos:     0x00,
			DataDecOffset: 0x00,
		}, nil
	}

	return Config{Type: TypeUnknown}, nil
}

// SigSize 根据 RSA_VER 字段返回签名长度。
// 不支持 RSA-1024（返回错误，与 C 一致）。
func SigSize(rawFw []byte, rsaVerPos int) (int, error) {
	if rsaVerPos < 0 || rsaVerPos+4 > len(rawFw) {
		return 0, fmt.Errorf("RSA_VER position out of range")
	}
	rsaVer := uint32(rawFw[rsaVerPos])<<24 |
		uint32(rawFw[rsaVerPos+1])<<16 |
		uint32(rawFw[rsaVerPos+2])<<8 |
		uint32(rawFw[rsaVerPos+3])

	switch rsaVer {
	case 0x200:
		return 0x100, nil
	case 0x100:
		return 0, fmt.Errorf("RSA-1024 not tested and firmware likely not encrypted")
	default:
		return 0, fmt.Errorf("unable to determine RSA (RSA_VER=0x%x)", rsaVer)
	}
}
