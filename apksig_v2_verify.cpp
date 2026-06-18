/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apksig_v2_verify.h"

#if defined(APKSIG_USE_OPENSSL)
#include <openssl/crypto.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#else
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/x509_crt.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <map>
#include <memory>
#include <limits>
#include <sstream>
#include <set>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kZipEocdSignature = 0x06054b50;
constexpr size_t kZipEocdMinSize = 22;
constexpr size_t kZipEocdMaxCommentSize = 0xffff;
constexpr size_t kZipEocdCdOffsetField = 16;
constexpr size_t kChunkSize = 1024 * 1024;
constexpr uint32_t kV2BlockId = 0x7109871a;
constexpr uint8_t kApkSigningBlockMagic[] = {
    0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
    0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32,
};

using Bytes = std::vector<uint8_t>;

#if defined(APKSIG_USE_OPENSSL)
template <typename T, void (*FreeFunc)(T*)>
using OpenSslPtr = std::unique_ptr<T, decltype(FreeFunc)>;
using EvpPkeyPtr = OpenSslPtr<EVP_PKEY, EVP_PKEY_free>;
using EvpMdCtxPtr = OpenSslPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using DsaPtr = OpenSslPtr<DSA, DSA_free>;
using X509Ptr = OpenSslPtr<X509, X509_free>;

void FreeOpenSslBuffer(uint8_t* p) {
  OPENSSL_free(p);
}

void FreeBio(BIO* p) {
  BIO_free(p);
}

using BioPtr = OpenSslPtr<BIO, FreeBio>;
#else
template <typename T, void (*FreeFunc)(T*)>
using MbedTlsPtr = std::unique_ptr<T, decltype(FreeFunc)>;

void FreeMbedTlsPk(mbedtls_pk_context* p) {
  mbedtls_pk_free(p);
  delete p;
}

void FreeMbedTlsX509(mbedtls_x509_crt* p) {
  mbedtls_x509_crt_free(p);
  delete p;
}

using MbedTlsPkPtr = MbedTlsPtr<mbedtls_pk_context, FreeMbedTlsPk>;
using MbedTlsX509Ptr = MbedTlsPtr<mbedtls_x509_crt, FreeMbedTlsX509>;
#endif

struct Slice {
  const uint8_t* data = nullptr;
  size_t size = 0;
};

struct ZipSections {
  size_t central_dir_offset = 0;
  size_t eocd_offset = 0;
  Bytes eocd;
};

struct ApkSigningBlock {
  Bytes block;
  size_t offset = 0;
};

struct ContentRange {
  bool from_file = false;
  size_t file_offset = 0;
  Slice memory;
  size_t size = 0;
};

enum class DigestKind {
  kChunkedSha256,
  kChunkedSha512,
};

struct SigAlgorithm {
  uint32_t id;
  const char* name;
  DigestKind digest_kind;
#if defined(APKSIG_USE_OPENSSL)
  const EVP_MD* (*md)();
#endif
  bool rsa_pss;
  int rsa_pss_salt_len;
  bool dsa;
};

struct SignerDigest {
  uint32_t sig_algorithm_id;
  DigestKind digest_kind;
  Bytes digest;
};

struct VerifiedSigner {
  std::vector<uint32_t> signature_algorithm_ids;
  std::vector<SignerDigest> digests;
};

bool Fail(const std::string& message, std::string* error) {
  *error = message;
  return false;
}

uint16_t GetLe16(const uint8_t* p) {
  return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t GetLe32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t GetLe64(const uint8_t* p) {
  uint64_t result = 0;
  for (int i = 7; i >= 0; --i) {
    result = (result << 8) | p[i];
  }
  return result;
}

void PutLe32(uint8_t* p, uint32_t value) {
  p[0] = value & 0xff;
  p[1] = (value >> 8) & 0xff;
  p[2] = (value >> 16) & 0xff;
  p[3] = (value >> 24) & 0xff;
}

std::string Hex(const uint8_t* data, size_t size) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 0x0f]);
  }
  return out;
}

std::string HexInt(uint32_t value) {
  std::ostringstream out;
  out << std::hex << value;
  return out.str();
}

bool GetFileSize(std::ifstream* in, size_t* size, std::string* error) {
  in->seekg(0, std::ios::end);
  const std::streamoff end = in->tellg();
  if (end < 0) {
    return Fail("failed to determine APK size", error);
  }
  *size = static_cast<size_t>(end);
  in->seekg(0, std::ios::beg);
  return true;
}

bool ReadAt(std::ifstream* in, size_t offset, size_t size, Bytes* out, std::string* error) {
  out->resize(size);
  in->clear();
  in->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!*in) {
    return Fail("failed to seek APK", error);
  }
  if (size == 0) {
    return true;
  }
  in->read(reinterpret_cast<char*>(out->data()), static_cast<std::streamsize>(size));
  if (in->gcount() != static_cast<std::streamsize>(size)) {
    return Fail("failed to read APK", error);
  }
  return true;
}

#if defined(APKSIG_USE_OPENSSL)
bool EncodePublicKey(EVP_PKEY* pkey, Bytes* out, std::string* error) {
  uint8_t* encoded = nullptr;
  const int encoded_len = i2d_PUBKEY(pkey, &encoded);
  if (encoded_len <= 0 || encoded == nullptr) {
    return Fail("failed to encode certificate public key", error);
  }
  std::unique_ptr<uint8_t, decltype(FreeOpenSslBuffer)*> encoded_ptr(encoded, FreeOpenSslBuffer);
  out->assign(encoded, encoded + encoded_len);
  return true;
}

bool LoadCertificatePublicKey(const char* path, Bytes* public_key, std::string* error) {
  BioPtr bio(BIO_new_file(path, "rb"), FreeBio);
  if (!bio) {
    return Fail(std::string("failed to open certificate ") + path, error);
  }
  X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
  if (!cert) {
    BIO_free(bio.release());
    bio.reset(BIO_new_file(path, "rb"));
    if (!bio) {
      return Fail(std::string("failed to open certificate ") + path, error);
    }
    cert.reset(d2i_X509_bio(bio.get(), nullptr));
  }
  if (!cert) {
    return Fail("failed to parse trusted certificate", error);
  }
  EvpPkeyPtr cert_key(X509_get_pubkey(cert.get()), EVP_PKEY_free);
  if (!cert_key) {
    return Fail("failed to extract public key from trusted certificate", error);
  }
  return EncodePublicKey(cert_key.get(), public_key, error);
}
#else
bool LoadCertificatePublicKey(const char* path, Bytes* public_key, std::string* error) {
  Bytes cert_bytes;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return Fail(std::string("failed to open certificate ") + path, error);
  }
  in.seekg(0, std::ios::end);
  const std::streamoff size = in.tellg();
  if (size < 0) {
    return Fail("failed to determine certificate size", error);
  }
  in.seekg(0, std::ios::beg);
  cert_bytes.resize(static_cast<size_t>(size));
  if (!cert_bytes.empty()) {
    in.read(reinterpret_cast<char*>(cert_bytes.data()),
            static_cast<std::streamsize>(cert_bytes.size()));
    if (in.gcount() != static_cast<std::streamsize>(cert_bytes.size())) {
      return Fail("failed to read certificate", error);
    }
  }

  MbedTlsX509Ptr cert(new mbedtls_x509_crt, FreeMbedTlsX509);
  mbedtls_x509_crt_init(cert.get());
  Bytes pem_bytes = cert_bytes;
  pem_bytes.push_back(0);
  int ret = mbedtls_x509_crt_parse(cert.get(), pem_bytes.data(), pem_bytes.size());
  if (ret != 0) {
    ret = mbedtls_x509_crt_parse_der(cert.get(), cert_bytes.data(), cert_bytes.size());
  }
  if (ret != 0) {
    return Fail("failed to parse trusted certificate", error);
  }

  Bytes encoded(4096);
  int encoded_len = 0;
  for (;;) {
    encoded_len = mbedtls_pk_write_pubkey_der(&cert->pk, encoded.data(), encoded.size());
    if (encoded_len >= 0) {
      break;
    }
    if (encoded.size() >= 64 * 1024) {
      return Fail("failed to encode certificate public key", error);
    }
    encoded.resize(encoded.size() * 2);
  }
  public_key->assign(encoded.data() + encoded.size() - encoded_len, encoded.data() + encoded.size());
  return true;
}
#endif

bool ReadLengthPrefixedSlice(Slice* input, Slice* out, std::string* error) {
  if (input->size < 4) {
    return Fail("truncated length-prefixed field", error);
  }
  const uint32_t len = GetLe32(input->data);
  input->data += 4;
  input->size -= 4;
  if (len > input->size) {
    return Fail("length-prefixed field exceeds remaining input", error);
  }
  out->data = input->data;
  out->size = len;
  input->data += len;
  input->size -= len;
  return true;
}

bool ReadLengthPrefixedBytes(Slice* input, Bytes* out, std::string* error) {
  Slice slice;
  if (!ReadLengthPrefixedSlice(input, &slice, error)) {
    return false;
  }
  out->assign(slice.data, slice.data + slice.size);
  return true;
}

bool FindZipSections(std::ifstream* apk, size_t apk_size, ZipSections* sections,
                     std::string* error) {
  if (apk_size < kZipEocdMinSize) {
    return Fail("APK too small to contain ZIP EOCD", error);
  }
  const size_t search_size = std::min(apk_size, kZipEocdMinSize + kZipEocdMaxCommentSize);
  const size_t search_start = apk_size - search_size;
  Bytes tail;
  if (!ReadAt(apk, search_start, search_size, &tail, error)) {
    return false;
  }
  for (size_t off = search_size - kZipEocdMinSize + 1; off-- > 0;) {
    if (GetLe32(tail.data() + off) != kZipEocdSignature) {
      continue;
    }
    const size_t comment_len = GetLe16(tail.data() + off + 20);
    const size_t eocd_offset = search_start + off;
    if (eocd_offset + kZipEocdMinSize + comment_len != apk_size) {
      continue;
    }
    const uint32_t cd_offset = GetLe32(tail.data() + off + kZipEocdCdOffsetField);
    if (cd_offset > eocd_offset) {
      return Fail("ZIP central directory offset is past EOCD", error);
    }
    sections->central_dir_offset = cd_offset;
    sections->eocd_offset = eocd_offset;
    sections->eocd.assign(tail.data() + off, tail.data() + search_size);
    return true;
  }
  return Fail("ZIP EOCD not found", error);
}

bool FindApkSigningBlock(std::ifstream* apk, const ZipSections& sections,
                         ApkSigningBlock* signing, std::string* error) {
  if (sections.central_dir_offset < 32) {
    return Fail("APK Signing Block footer not present before Central Directory", error);
  }
  const size_t footer = sections.central_dir_offset - 24;
  Bytes footer_bytes;
  if (!ReadAt(apk, footer, 24, &footer_bytes, error)) {
    return false;
  }
  if (std::memcmp(footer_bytes.data() + 8, kApkSigningBlockMagic,
                  sizeof(kApkSigningBlockMagic)) != 0) {
    return Fail("APK Signing Block magic not found", error);
  }
  const uint64_t size_in_footer = GetLe64(footer_bytes.data());
  if (size_in_footer < 24 || size_in_footer > sections.central_dir_offset - 8) {
    return Fail("APK Signing Block size is out of range", error);
  }
  const size_t block_size = static_cast<size_t>(size_in_footer) + 8;
  const size_t block_offset = sections.central_dir_offset - block_size;
  if (!ReadAt(apk, block_offset, block_size, &signing->block, error)) {
    return false;
  }
  const uint64_t size_in_header = GetLe64(signing->block.data());
  if (size_in_header != size_in_footer) {
    return Fail("APK Signing Block header/footer sizes do not match", error);
  }
  signing->offset = block_offset;
  return true;
}

bool FindV2Block(const ApkSigningBlock& signing, Slice* v2_block, std::string* error) {
  if (signing.block.size() < 32) {
    return Fail("APK Signing Block too small", error);
  }
  Slice pairs{signing.block.data() + 8, signing.block.size() - 32};
  while (pairs.size > 0) {
    if (pairs.size < 8) {
      return Fail("truncated APK Signing Block entry size", error);
    }
    const uint64_t len64 = GetLe64(pairs.data);
    pairs.data += 8;
    pairs.size -= 8;
    if (len64 < 4 || len64 > pairs.size) {
      return Fail("APK Signing Block entry size is out of range", error);
    }
    const size_t len = static_cast<size_t>(len64);
    const uint32_t id = GetLe32(pairs.data);
    if (id == kV2BlockId) {
      *v2_block = {pairs.data + 4, len - 4};
      return true;
    }
    pairs.data += len;
    pairs.size -= len;
  }
  return Fail("APK Signature Scheme v2 block not found", error);
}

const SigAlgorithm* FindAlgorithm(uint32_t id) {
  static const SigAlgorithm kAlgorithms[] = {
#if defined(APKSIG_USE_OPENSSL)
      {0x0101, "RSA-PSS-SHA256", DigestKind::kChunkedSha256, EVP_sha256, true, 32, false},
      {0x0102, "RSA-PSS-SHA512", DigestKind::kChunkedSha512, EVP_sha512, true, 64, false},
      {0x0103, "RSA-PKCS1-SHA256", DigestKind::kChunkedSha256, EVP_sha256, false, 0, false},
      {0x0104, "RSA-PKCS1-SHA512", DigestKind::kChunkedSha512, EVP_sha512, false, 0, false},
      {0x0201, "ECDSA-SHA256", DigestKind::kChunkedSha256, EVP_sha256, false, 0, false},
      {0x0202, "ECDSA-SHA512", DigestKind::kChunkedSha512, EVP_sha512, false, 0, false},
      {0x0301, "DSA-SHA256", DigestKind::kChunkedSha256, EVP_sha256, false, 0, true},
#else
      {0x0101, "RSA-PSS-SHA256", DigestKind::kChunkedSha256, true, 32, false},
      {0x0102, "RSA-PSS-SHA512", DigestKind::kChunkedSha512, true, 64, false},
      {0x0103, "RSA-PKCS1-SHA256", DigestKind::kChunkedSha256, false, 0, false},
      {0x0104, "RSA-PKCS1-SHA512", DigestKind::kChunkedSha512, false, 0, false},
      {0x0201, "ECDSA-SHA256", DigestKind::kChunkedSha256, false, 0, false},
      {0x0202, "ECDSA-SHA512", DigestKind::kChunkedSha512, false, 0, false},
      {0x0301, "DSA-SHA256", DigestKind::kChunkedSha256, false, 0, true},
#endif
  };
  for (const auto& alg : kAlgorithms) {
    if (alg.id == id) {
      return &alg;
    }
  }
  return nullptr;
}

#if defined(APKSIG_USE_OPENSSL)
bool DigestBytes(const EVP_MD* md, const uint8_t* data, size_t size, Bytes* out,
                 std::string* error);
bool DigestSlices(const EVP_MD* md, const std::vector<Slice>& slices, Bytes* out,
                  std::string* error);
#else
bool DigestBytes(DigestKind kind, const uint8_t* data, size_t size, Bytes* out,
                 std::string* error);
bool DigestSlices(DigestKind kind, const std::vector<Slice>& slices, Bytes* out,
                  std::string* error);
#endif

bool VerifySignature(const SigAlgorithm& alg, const Bytes& public_key, Slice signed_data,
                     const Bytes& signature, std::string* error) {
#if defined(APKSIG_USE_OPENSSL)
  const uint8_t* p = public_key.data();
  EvpPkeyPtr pkey(d2i_PUBKEY(nullptr, &p, public_key.size()), EVP_PKEY_free);
  if (!pkey || p != public_key.data() + public_key.size()) {
    return Fail("failed to parse signer's SubjectPublicKeyInfo", error);
  }

  if (alg.dsa) {
    Bytes digest;
    if (!DigestBytes(alg.md(), signed_data.data, signed_data.size, &digest, error)) {
      return false;
    }
    DsaPtr dsa(EVP_PKEY_get1_DSA(pkey.get()), DSA_free);
    if (!dsa) {
      return Fail("failed to extract DSA public key", error);
    }
    if (DSA_verify(0, digest.data(), digest.size(), signature.data(), signature.size(),
                   dsa.get()) != 1) {
      return Fail(std::string(alg.name) + " signature over signed-data did not verify", error);
    }
    return true;
  }

  EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!ctx) {
    return Fail("failed to allocate EVP_MD_CTX", error);
  }
  EVP_PKEY_CTX* pkey_ctx = nullptr;
  if (EVP_DigestVerifyInit(ctx.get(), &pkey_ctx, alg.md(), nullptr, pkey.get()) != 1) {
    return Fail(std::string("EVP_DigestVerifyInit failed for ") + alg.name, error);
  }
  if (alg.rsa_pss) {
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, alg.md()) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, alg.rsa_pss_salt_len) != 1) {
      return Fail("failed to configure RSA-PSS parameters", error);
    }
  }
  if (EVP_DigestVerifyUpdate(ctx.get(), signed_data.data, signed_data.size) != 1) {
    return Fail("EVP_DigestVerifyUpdate failed", error);
  }
  if (EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) != 1) {
    return Fail(std::string(alg.name) + " signature over signed-data did not verify", error);
  }
  return true;
#else
  MbedTlsPkPtr pkey(new mbedtls_pk_context, FreeMbedTlsPk);
  mbedtls_pk_init(pkey.get());
  if (mbedtls_pk_parse_public_key(pkey.get(), public_key.data(), public_key.size()) != 0) {
    return Fail("failed to parse signer's SubjectPublicKeyInfo", error);
  }
  if (alg.dsa) {
    return Fail("DSA signatures are not supported by the mbedTLS backend", error);
  }

  Bytes digest;
  if (!DigestBytes(alg.digest_kind, signed_data.data, signed_data.size, &digest, error)) {
    return false;
  }
  const mbedtls_md_type_t md_alg =
      alg.digest_kind == DigestKind::kChunkedSha256 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA512;
  int ret = 0;
  if (alg.rsa_pss) {
    mbedtls_pk_rsassa_pss_options options;
    options.mgf1_hash_id = md_alg;
    options.expected_salt_len = alg.rsa_pss_salt_len;
    ret = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &options, pkey.get(), md_alg,
                                digest.data(), digest.size(), signature.data(), signature.size());
  } else {
    ret = mbedtls_pk_verify(pkey.get(), md_alg, digest.data(), digest.size(), signature.data(),
                            signature.size());
  }
  if (ret != 0) {
    return Fail(std::string(alg.name) + " signature over signed-data did not verify", error);
  }
  return true;
#endif
}

bool PublicKeyMatchesFirstCertificate(const Bytes& public_key, const std::vector<Bytes>& certs,
                                      std::string* error) {
  if (certs.empty()) {
    return Fail("v2 signer has no certificates", error);
  }
#if defined(APKSIG_USE_OPENSSL)
  const uint8_t* p = certs[0].data();
  X509Ptr cert(d2i_X509(nullptr, &p, certs[0].size()), X509_free);
  if (!cert || p != certs[0].data() + certs[0].size()) {
    return Fail("failed to parse first signer certificate", error);
  }
  EvpPkeyPtr cert_key(X509_get_pubkey(cert.get()), EVP_PKEY_free);
  if (!cert_key) {
    return Fail("failed to extract public key from first signer certificate", error);
  }
  uint8_t* encoded = nullptr;
  const int encoded_len = i2d_PUBKEY(cert_key.get(), &encoded);
  if (encoded_len <= 0 || encoded == nullptr) {
    return Fail("failed to encode certificate public key", error);
  }
  std::unique_ptr<uint8_t, decltype(FreeOpenSslBuffer)*> encoded_ptr(encoded, FreeOpenSslBuffer);
  if (public_key.size() != static_cast<size_t>(encoded_len) ||
      std::memcmp(public_key.data(), encoded, encoded_len) != 0) {
    return Fail("public key in signatures record does not match first certificate", error);
  }
  return true;
#else
  MbedTlsX509Ptr cert(new mbedtls_x509_crt, FreeMbedTlsX509);
  mbedtls_x509_crt_init(cert.get());
  if (mbedtls_x509_crt_parse_der(cert.get(), certs[0].data(), certs[0].size()) != 0) {
    return Fail("failed to parse first signer certificate", error);
  }

  Bytes encoded(std::max<size_t>(public_key.size() + 512, 4096));
  int encoded_len = 0;
  for (;;) {
    encoded_len = mbedtls_pk_write_pubkey_der(&cert->pk, encoded.data(), encoded.size());
    if (encoded_len >= 0) {
      break;
    }
    if (encoded.size() >= 64 * 1024) {
      return Fail("failed to encode certificate public key", error);
    }
    encoded.resize(encoded.size() * 2);
  }
  const uint8_t* encoded_data = encoded.data() + encoded.size() - encoded_len;
  if (public_key.size() != static_cast<size_t>(encoded_len) ||
      std::memcmp(public_key.data(), encoded_data, encoded_len) != 0) {
    return Fail("public key in signatures record does not match first certificate", error);
  }
  return true;
#endif
}

bool ParseSigner(Slice signer, const Bytes& trusted_public_key, VerifiedSigner* out,
                 std::string* error) {
  Slice signed_data;
  Slice signatures;
  Bytes public_key;
  if (!ReadLengthPrefixedSlice(&signer, &signed_data, error) ||
      !ReadLengthPrefixedSlice(&signer, &signatures, error) ||
      !ReadLengthPrefixedBytes(&signer, &public_key, error)) {
    return false;
  }
  if (signer.size != 0) {
    return Fail("unexpected trailing data in v2 signer block", error);
  }

  std::map<uint32_t, Bytes> supported_signatures_by_alg;
  while (signatures.size > 0) {
    Slice record;
    if (!ReadLengthPrefixedSlice(&signatures, &record, error)) {
      return false;
    }
    if (record.size < 8) {
      return Fail("malformed v2 signature record", error);
    }
    const uint32_t alg_id = GetLe32(record.data);
    record.data += 4;
    record.size -= 4;
    Bytes sig;
    if (!ReadLengthPrefixedBytes(&record, &sig, error)) {
      return false;
    }
    if (record.size != 0) {
      return Fail("unexpected trailing data in v2 signature record", error);
    }
    if (FindAlgorithm(alg_id) != nullptr) {
      supported_signatures_by_alg[alg_id] = sig;
    }
    out->signature_algorithm_ids.push_back(alg_id);
  }
  if (out->signature_algorithm_ids.empty()) {
    return Fail("v2 signer has no signatures", error);
  }
  if (supported_signatures_by_alg.empty()) {
    return Fail("v2 signer has no supported signatures", error);
  }
  if (public_key != trusted_public_key) {
    return Fail("signer public key does not match trusted certificate", error);
  }

  const auto best = std::max_element(
      supported_signatures_by_alg.begin(), supported_signatures_by_alg.end(),
      [](const auto& a, const auto& b) {
        const SigAlgorithm* alg_a = FindAlgorithm(a.first);
        const SigAlgorithm* alg_b = FindAlgorithm(b.first);
        return static_cast<int>(alg_a->digest_kind) < static_cast<int>(alg_b->digest_kind);
      });
  const SigAlgorithm* best_alg = FindAlgorithm(best->first);
  if (!VerifySignature(*best_alg, trusted_public_key, signed_data, best->second, error)) {
    return false;
  }

  Slice signed_data_copy = signed_data;
  Slice digests;
  Slice certificates;
  Slice additional_attributes;
  if (!ReadLengthPrefixedSlice(&signed_data_copy, &digests, error) ||
      !ReadLengthPrefixedSlice(&signed_data_copy, &certificates, error) ||
      !ReadLengthPrefixedSlice(&signed_data_copy, &additional_attributes, error)) {
    return false;
  }
  if (signed_data_copy.size == 4 && GetLe32(signed_data_copy.data) == 0) {
    signed_data_copy.data += 4;
    signed_data_copy.size = 0;
  }
  if (signed_data_copy.size != 0) {
    return Fail("unexpected trailing data in signed-data", error);
  }

  std::vector<Bytes> certs;
  while (certificates.size > 0) {
    Bytes cert;
    if (!ReadLengthPrefixedBytes(&certificates, &cert, error)) {
      return false;
    }
    certs.push_back(std::move(cert));
  }
  if (!PublicKeyMatchesFirstCertificate(public_key, certs, error)) {
    return false;
  }

  std::vector<uint32_t> digest_alg_ids;
  std::vector<uint32_t> supported_digest_alg_ids;
  while (digests.size > 0) {
    Slice record;
    if (!ReadLengthPrefixedSlice(&digests, &record, error)) {
      return false;
    }
    if (record.size < 8) {
      return Fail("malformed v2 digest record", error);
    }
    const uint32_t alg_id = GetLe32(record.data);
    record.data += 4;
    record.size -= 4;
    Bytes digest;
    if (!ReadLengthPrefixedBytes(&record, &digest, error)) {
      return false;
    }
    if (record.size != 0) {
      return Fail("unexpected trailing data in v2 digest record", error);
    }
    const SigAlgorithm* alg = FindAlgorithm(alg_id);
    if (alg != nullptr) {
      out->digests.push_back({alg_id, alg->digest_kind, std::move(digest)});
      supported_digest_alg_ids.push_back(alg_id);
    }
    digest_alg_ids.push_back(alg_id);
  }

  if (out->signature_algorithm_ids != digest_alg_ids) {
    return Fail("signature algorithm IDs differ between signatures and digests records", error);
  }
  if (supported_digest_alg_ids.empty()) {
    return Fail("v2 signer has no supported content digests", error);
  }
  (void)additional_attributes;
  return true;
}

bool ParseV2Block(Slice v2_block, const Bytes& trusted_public_key,
                  std::vector<VerifiedSigner>* signers, std::string* error) {
  Slice signer_sequence;
  if (!ReadLengthPrefixedSlice(&v2_block, &signer_sequence, error)) {
    return false;
  }
  if (v2_block.size != 0) {
    return Fail("unexpected trailing data in APK Signature Scheme v2 block", error);
  }
  if (signer_sequence.size == 0) {
    return Fail("APK Signature Scheme v2 block contains no signers", error);
  }
  while (signer_sequence.size > 0) {
    Slice signer_block;
    if (!ReadLengthPrefixedSlice(&signer_sequence, &signer_block, error)) {
      return false;
    }
    VerifiedSigner signer;
    if (!ParseSigner(signer_block, trusted_public_key, &signer, error)) {
      return false;
    }
    signers->push_back(std::move(signer));
  }
  return true;
}

#if defined(APKSIG_USE_OPENSSL)
const EVP_MD* DigestMd(DigestKind kind) {
  return kind == DigestKind::kChunkedSha256 ? EVP_sha256() : EVP_sha512();
}
#endif

size_t DigestSize(DigestKind kind) {
  return kind == DigestKind::kChunkedSha256 ? 32 : 64;
}

#if defined(APKSIG_USE_OPENSSL)
bool DigestBytes(const EVP_MD* md, const uint8_t* data, size_t size, Bytes* out,
                 std::string* error) {
  return DigestSlices(md, {{data, size}}, out, error);
}

bool DigestSlices(const EVP_MD* md, const std::vector<Slice>& slices, Bytes* out,
                  std::string* error) {
  EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!ctx) {
    return Fail("failed to allocate digest context", error);
  }
  out->resize(EVP_MD_size(md));
  unsigned int out_len = 0;
  if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
    return Fail("digest computation failed", error);
  }
  for (const Slice& slice : slices) {
    if (EVP_DigestUpdate(ctx.get(), slice.data, slice.size) != 1) {
      return Fail("digest computation failed", error);
    }
  }
  if (EVP_DigestFinal_ex(ctx.get(), out->data(), &out_len) != 1) {
    return Fail("digest computation failed", error);
  }
  out->resize(out_len);
  return true;
}
#else
bool DigestBytes(DigestKind kind, const uint8_t* data, size_t size, Bytes* out,
                 std::string* error) {
  return DigestSlices(kind, {{data, size}}, out, error);
}

bool DigestSlices(DigestKind kind, const std::vector<Slice>& slices, Bytes* out,
                  std::string* error) {
  out->resize(DigestSize(kind));
  if (kind == DigestKind::kChunkedSha256) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int ret = mbedtls_sha256_starts(&ctx, 0);
    for (const Slice& slice : slices) {
      if (ret == 0) {
        ret = mbedtls_sha256_update(&ctx, slice.data, slice.size);
      }
    }
    if (ret == 0) {
      ret = mbedtls_sha256_finish(&ctx, out->data());
    }
    mbedtls_sha256_free(&ctx);
    if (ret != 0) {
      return Fail("digest computation failed", error);
    }
  } else {
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    int ret = mbedtls_sha512_starts(&ctx, 0);
    for (const Slice& slice : slices) {
      if (ret == 0) {
        ret = mbedtls_sha512_update(&ctx, slice.data, slice.size);
      }
    }
    if (ret == 0) {
      ret = mbedtls_sha512_finish(&ctx, out->data());
    }
    mbedtls_sha512_free(&ctx);
    if (ret != 0) {
      return Fail("digest computation failed", error);
    }
  }
  return true;
}
#endif

bool DigestChunk(DigestKind kind, const uint8_t* data, size_t size, Bytes* out,
                 std::string* error) {
  uint8_t prefix[5] = {0xa5, 0, 0, 0, 0};
  PutLe32(prefix + 1, static_cast<uint32_t>(size));
  const std::vector<Slice> chunk_slices = {
      {prefix, sizeof(prefix)},
      {data, size},
  };
  return DigestSlices(
#if defined(APKSIG_USE_OPENSSL)
      DigestMd(kind),
#else
      kind,
#endif
      chunk_slices, out, error);
}

bool ComputeChunkedDigest(std::ifstream* apk, const std::vector<ContentRange>& contents,
                          DigestKind kind, Bytes* out, std::string* error) {
  size_t chunk_count = 0;
  for (const ContentRange& content : contents) {
    chunk_count += (content.size + kChunkSize - 1) / kChunkSize;
  }
  if (chunk_count > (std::numeric_limits<uint32_t>::max)()) {
    return Fail("APK has too many chunks", error);
  }
  const size_t digest_size = DigestSize(kind);
  Bytes chunk_digests(5 + chunk_count * digest_size);
  chunk_digests[0] = 0x5a;
  PutLe32(chunk_digests.data() + 1, static_cast<uint32_t>(chunk_count));

  size_t chunk_index = 0;
  for (const ContentRange& content : contents) {
    size_t offset = 0;
    while (offset < content.size) {
      const size_t chunk_size = std::min(kChunkSize, content.size - offset);
      Bytes chunk_digest;
      const uint8_t* chunk_data = nullptr;
      if (content.from_file) {
        Bytes read;
        if (!ReadAt(apk, content.file_offset + offset, chunk_size, &read, error)) {
          return false;
        }
        chunk_data = read.data();
        if (!DigestChunk(kind, chunk_data, chunk_size, &chunk_digest, error) ||
            chunk_digest.size() != digest_size) {
          return Fail("chunk digest computation failed", error);
        }
      } else {
        chunk_data = content.memory.data + offset;
        if (!DigestChunk(kind, chunk_data, chunk_size, &chunk_digest, error) ||
            chunk_digest.size() != digest_size) {
          return Fail("chunk digest computation failed", error);
        }
      }
      if (chunk_digest.size() != digest_size) {
        return Fail("chunk digest computation failed", error);
      }
      std::memcpy(chunk_digests.data() + 5 + chunk_index * digest_size, chunk_digest.data(),
                  digest_size);
      offset += chunk_size;
      ++chunk_index;
    }
  }
  return DigestBytes(
#if defined(APKSIG_USE_OPENSSL)
      DigestMd(kind),
#else
      kind,
#endif
      chunk_digests.data(), chunk_digests.size(), out, error);
}

bool VerifyContentDigests(std::ifstream* apk, const ZipSections& sections,
                          const ApkSigningBlock& signing,
                          const std::vector<VerifiedSigner>& signers, std::string* error) {
  std::set<DigestKind> kinds;
  for (const VerifiedSigner& signer : signers) {
    for (const SignerDigest& digest : signer.digests) {
      kinds.insert(digest.digest_kind);
    }
  }
  if (kinds.empty()) {
    return Fail("no supported content digests found", error);
  }

  Bytes modified_eocd = sections.eocd;
  PutLe32(modified_eocd.data() + kZipEocdCdOffsetField, static_cast<uint32_t>(signing.offset));
  const std::vector<ContentRange> contents = {
      {true, 0, {}, signing.offset},
      {true, sections.central_dir_offset, {}, sections.eocd_offset - sections.central_dir_offset},
      {false, 0, {modified_eocd.data(), modified_eocd.size()}, modified_eocd.size()},
  };

  std::map<DigestKind, Bytes> actual;
  for (DigestKind kind : kinds) {
    Bytes digest;
    if (!ComputeChunkedDigest(apk, contents, kind, &digest, error)) {
      return false;
    }
    actual[kind] = std::move(digest);
  }

  for (const VerifiedSigner& signer : signers) {
    for (const SignerDigest& expected : signer.digests) {
      const Bytes& got = actual[expected.digest_kind];
      if (got != expected.digest) {
        return Fail("APK content digest mismatch for signature algorithm 0x" +
                        HexInt(expected.sig_algorithm_id) +
                        ": expected " + Hex(expected.digest.data(), expected.digest.size()) +
                        ", actual " + Hex(got.data(), got.size()),
                    error);
      }
    }
  }
  return true;
}

}  // namespace

bool ApkSigV2Verifier::Verify(const char* path, const char* cert_path,
                              std::string* error) const {
  Bytes trusted_public_key;
  if (!LoadCertificatePublicKey(cert_path, &trusted_public_key, error)) {
    return false;
  }
  std::ifstream apk(path, std::ios::binary);
  if (!apk) {
    return Fail(std::string("failed to open ") + path, error);
  }
  size_t apk_size = 0;
  ZipSections sections;
  ApkSigningBlock signing;
  Slice v2_block;
  std::vector<VerifiedSigner> signers;
  return GetFileSize(&apk, &apk_size, error) && FindZipSections(&apk, apk_size, &sections, error) &&
         FindApkSigningBlock(&apk, sections, &signing, error) &&
         FindV2Block(signing, &v2_block, error) &&
         ParseV2Block(v2_block, trusted_public_key, &signers, error) &&
         VerifyContentDigests(&apk, sections, signing, signers, error);
}

void PrintUsage(const char* program, FILE* out) {
  std::fprintf(out,
               "Usage:\n"
               "  %s --apk APK --cert CERT\n"
               "  %s -a APK -c CERT\n"
               "  %s APK CERT\n"
               "\n"
               "Verify an APK/ZIP file signed with APK Signature Scheme v2.\n"
               "\n"
               "Options:\n"
               "  -a, --apk APK       APK or ZIP file to verify\n"
               "  -c, --cert CERT     trusted X.509 certificate, PEM or DER\n"
               "  -h, --help          show this help message\n",
               program, program, program);
}

int main(int argc, char** argv) {
  const char* apk_path = nullptr;
  const char* cert_path = nullptr;
  const option long_options[] = {
      {"apk", required_argument, nullptr, 'a'},
      {"cert", required_argument, nullptr, 'c'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0},
  };

  for (;;) {
    const int opt = getopt_long(argc, argv, "a:c:h", long_options, nullptr);
    if (opt == -1) {
      break;
    }
    switch (opt) {
      case 'a':
        apk_path = optarg;
        break;
      case 'c':
        cert_path = optarg;
        break;
      case 'h':
        PrintUsage(argv[0], stdout);
        return 0;
      default:
        PrintUsage(argv[0], stderr);
        return 2;
    }
  }

  const int positional_count = argc - optind;
  if (positional_count > 0) {
    if (positional_count != 2 || apk_path != nullptr || cert_path != nullptr) {
      PrintUsage(argv[0], stderr);
      return 2;
    }
    apk_path = argv[optind];
    cert_path = argv[optind + 1];
  }

  if (apk_path == nullptr || cert_path == nullptr) {
    PrintUsage(argv[0], stderr);
    return 2;
  }

  std::string error;
  ApkSigV2Verifier verifier;
  if (!verifier.Verify(apk_path, cert_path, &error)) {
    std::fprintf(stderr, "APK Signature Scheme v2 verification failed: %s\n", error.c_str());
    return 1;
  }
  std::printf("APK Signature Scheme v2 verified\n");
  return 0;
}
