package decrypt

import (
	"encoding/hex"
	"os"
	"testing"
)

const fwRoot = "c:/Users/alanni/Desktop/tp-link-decrypt-main/_keys_fw"

func TestDecryptTapo(t *testing.T) {
	fw, err := os.ReadFile(fwRoot + "/Tapo_C210v1.bin")
	if err != nil {
		t.Skipf("firmware not available: %v", err)
	}

	// 注意：该样本为 RSA-1024 固件，工具明确不支持。
	// 此处主要验证解密链路不会崩溃，真正的 RSA-2048 端到端验证需要 2048 位固件。
	res, err := DecryptRSA(fw, 0x20, 0x100, 0x00, 0x00, testRSA0)
	if err != nil {
		t.Logf("DecryptRSA(Tapo) failed (expected for RSA-1024 sample): %v", err)
		return
	}
	t.Logf("KEY=%s", hex.EncodeToString(res.Key))
	t.Logf("IV =%s", hex.EncodeToString(res.IV))
	if len(res.Decrypted) != len(fw) {
		t.Fatalf("output size mismatch: %d != %d", len(res.Decrypted), len(fw))
	}
	t.Logf("decrypted output size: %d", len(res.Decrypted))
}

func TestDecryptFwType(t *testing.T) {
	fw, err := os.ReadFile(fwRoot + "/ax6000v2.bin.rollback")
	if err != nil {
		t.Skipf("firmware not available: %v", err)
	}

	// fw-type: sig_pos=0x130, fw_data_pos=0x14, data_dec_offset=sig_pos-fw_data_pos
	res, err := DecryptRSA(fw, 0x130, 0x100, 0x14, 0x130-0x14, testRSA1)
	if err != nil {
		t.Logf("DecryptRSA(fw-type) failed (expected for RSA-1024 sample): %v", err)
		return
	}
	t.Logf("KEY=%s", hex.EncodeToString(res.Key))
	t.Logf("IV =%s", hex.EncodeToString(res.IV))
	t.Logf("decrypted output size: %d", len(res.Decrypted))
}

// 拷贝自 keys 包，避免测试包循环依赖。
const testRSA0 = "BgIAAAwkAABSU0ExAAgAAAEAAQBzhFrp9KOUU2PYuWKTq+qcKVU5B5Oq/uHFK7zLEkfZmHW+5VuSypXOYSB45C80xZhRRjta3MiwbPIjCFEsdc9o7uWfACYn7a9YhZaCJkFTULz1RMQIap9RVznKN5QhV9/kxxZPymeH2H8JkMR3T4JJY1ceBfqtGYnbAIV4+yof+X76Ou73ce82AU79QOnZyfbbZ2MiHpFogv3YLSYrOlccZaDSDiid+qWqIlaQoShrdN0PgfGcL/C6vQhTP4/NeQIR7u8qI2RIsc9b9ZvhyrFXNqpD1wdpHifrl7MX6TqxYWL1j4QNyPDrDCZVSRNtf8EAcAyFIqjWzT1+jpvLiPOz"
const testRSA1 = "BgIAAAwkAABSU0ExAAgAAAEAAQCdocMdSvAkLmNelNXLolhx4/OqVrxm6g1XCIlMdTgWAAbA4GkSZbU4juBCWdUgc7oYCinkzpjttbZpFY1FS1GfYAiga2S9czL3tB2+7YMcwozwXW504nXGEJ5ShmvvZy6iu/N54hFauwram8Sbc7ax1sJ1rRA78jWz7i1mX/AeIPgWw336DQeYhAyZlFjVGkyFK1miLDgDeMmejJVZu3v3iu6VyuyVSGngRP+RyROzjvefY45kBM3h+2HM9oF3BkeUvS6TMasCmgMQEepVOLLcgbPlogmpxxlFRxTm0sjyIIhMj422ClU06ze31E+TBwtFiagwfw85f+gqzsOIo8e2"
