// Package keys 内置 TP-Link 固件解密所需的 RSA/DES 密钥。
//
// 这些密钥由 extract_keys.sh 从官方固件中提取，并经过 SHA256 校验
// "0a7857d40fb02ff1b8d3cbce769e6c402a82a8094b4af553c54e4ffbdc4b6e64" 确认一致。
package keys

// RSA0 是 Tapo/IPC 类固件使用的 RSA-2048 公钥（MS PUBKEYBLOB，base64 编码）。
// 来源：Tapo_C210v1_en_1.3.1 固件中的 slpupgrade。
const RSA0 = "BgIAAAwkAABSU0ExAAgAAAEAAQBzhFrp9KOUU2PYuWKTq+qcKVU5B5Oq/uHFK7zLEkfZmHW+5VuSypXOYSB45C80xZhRRjta3MiwbPIjCFEsdc9o7uWfACYn7a9YhZaCJkFTULz1RMQIap9RVznKN5QhV9/kxxZPymeH2H8JkMR3T4JJY1ceBfqtGYnbAIV4+yof+X76Ou73ce82AU79QOnZyfbbZ2MiHpFogv3YLSYrOlccZaDSDiid+qWqIlaQoShrdN0PgfGcL/C6vQhTP4/NeQIR7u8qI2RIsc9b9ZvhyrFXNqpD1wdpHifrl7MX6TqxYWL1j4QNyPDrDCZVSRNtf8EAcAyFIqjWzT1+jpvLiPOz"

// RSA1 是 "fw-type:" 路由器/AP 固件使用的 RSA-2048 公钥（MS PUBKEYBLOB，base64 编码）。
// 来源：ax6000v2-up-ver1-1-2-P1 固件中的 nvrammanager。
const RSA1 = "BgIAAAwkAABSU0ExAAgAAAEAAQCdocMdSvAkLmNelNXLolhx4/OqVrxm6g1XCIlMdTgWAAbA4GkSZbU4juBCWdUgc7oYCinkzpjttbZpFY1FS1GfYAiga2S9czL3tB2+7YMcwozwXW504nXGEJ5ShmvvZy6iu/N54hFauwram8Sbc7ax1sJ1rRA78jWz7i1mX/AeIPgWw336DQeYhAyZlFjVGkyFK1miLDgDeMmejJVZu3v3iu6VyuyVSGngRP+RyROzjvefY45kBM3h+2HM9oF3BkeUvS6TMasCmgMQEepVOLLcgbPlogmpxxlFRxTm0sjyIIhMj422ClU06ze31E+TBwtFiagwfw85f+gqzsOIo8e2"

// DESKey 是 Switch（Omada）固件使用的 DES-CBC 解密密钥。
// 来源：rtk-maple_gpl.tar.gz 中的 libservice.so。
const DESKey = "0001020304050607"

// DESIV 是 Switch（Omada）固件使用的 DES-CBC 解密初始向量。
// 来源：rtk-maple_gpl.tar.gz 中的 libservice.so。
const DESIV = "f51010736efbabb2"
