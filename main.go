// tp-link-decrypt Go 重构版。
//
// 在保留原 C 工具全部解密能力（fw-type / Tapo RSA 验签 + AES-CBC 解密、
// 交换机 DES-CBC 解密）的基础上，提供一个基于 bubbletea 的 TUI 选项卡
// 交互式确认界面。密钥已内置（见 keys 包），无需再执行 extract_keys.sh。
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/watchfulip/go-tp-link-decrypt/internal/decrypt"
	"github.com/watchfulip/go-tp-link-decrypt/internal/fw"
	"github.com/watchfulip/go-tp-link-decrypt/internal/ui"
	"github.com/watchfulip/go-tp-link-decrypt/keys"
)

const (
	sigLen = 0x100 // RSA-2048 固定签名长度
)

// decryptOnce 执行一次真实的固件解密，返回日志信息与输出文件路径。
func decryptOnce(path, mode string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取固件失败: %w", err)
	}

	logs := []string{
		"已读取固件: " + path,
		"文件大小: " + fmt.Sprintf("%d 字节", len(raw)),
	}

	cfg, err := fw.Detect(raw)
	if err != nil {
		return nil, err
	}

	// 自动/强制模式覆盖
	switch mode {
	case "强制 fw-type":
		cfg.Type = fw.TypeFWType
	case "强制 Tapo":
		cfg.Type = fw.TypeTapo
	case "强制 Switch":
		cfg.Type = fw.TypeUnknown
	}

	var decrypted []byte
	switch cfg.Type {
	case fw.TypeUnknown: // Switch：DES-CBC
		logs = append(logs, "检测到 Switch 固件，使用 DES-CBC 解密")
		decrypted, err = decrypt.DecryptDES(raw, keys.DESKey, keys.DESIV)
		if err != nil {
			return nil, err
		}
		logs = append(logs, "DES-CBC 解密完成")

	case fw.TypeFWType:
		logs = append(logs, "检测到 fw-type: 固件")
		cfg.RSAKey = keys.RSA1
		decrypted, err = decryptRSA(raw, cfg, logs)
		if err != nil {
			return nil, err
		}
		logs = append(logs, "已记录 RSA_KEY=RSA1 (fw-type)")

	case fw.TypeTapo:
		logs = append(logs, "检测到 Tapo/IPC 固件")
		cfg.RSAKey = keys.RSA0
		decrypted, err = decryptRSA(raw, cfg, logs)
		if err != nil {
			return nil, err
		}
		logs = append(logs, "已记录 RSA_KEY=RSA0 (Tapo)")
	}

	// 写入 .dec 文件
	outPath := path + ".dec"
	if err := os.WriteFile(outPath, decrypted, 0644); err != nil {
		return nil, fmt.Errorf("写入输出文件失败: %w", err)
	}
	logs = append(logs, "解密成功，输出: "+outPath)

	return logs, nil
}

// decryptRSA 完成 RSA 验签 + AES-CBC 解密，并把日志追加到 logs 中。
func decryptRSA(raw []byte, cfg fw.Config, logs []string) ([]byte, error) {
	sigSize, err := fw.SigSize(raw, cfg.RSAVerPos)
	if err != nil {
		return nil, err
	}
	logs = append(logs, fmt.Sprintf("RSA_VER 签名长度: %d 字节", sigSize))

	res, err := decrypt.DecryptRSA(raw, cfg.SigPos, sigSize, cfg.FWDataPos, cfg.DataDecOffset, cfg.RSAKey)
	if err != nil {
		return nil, err
	}
	logs = append(logs, "RSA-PSS 验签通过")
	logs = append(logs, "AES KEY: "+fmt.Sprintf("%x", res.Key))
	logs = append(logs, "AES IV : "+fmt.Sprintf("%x", res.IV))
	logs = append(logs, "AES-128-CBC 解密完成")
	return res.Decrypted, nil
}

// runCLI 以命令行方式处理，供非 TUI 场景使用（例如直接传参）。
func runCLI(path string) ([]string, error) {
	return decryptOnce(path, "自动检测")
}

func main() {
	// 支持 CLI 用法：带参数时直接解密，不带参数时启动 TUI。
	if len(os.Args) >= 2 {
		logs, err := runCLI(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "解密失败:", err)
			os.Exit(1)
		}
		for _, l := range logs {
			fmt.Println(l)
		}
		return
	}

	handler := ui.Handler(decryptOnce)
	app := ui.New(handler)
	if _, err := tea.NewProgram(app, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "TUI 运行失败:", err)
		os.Exit(1)
	}
}
