<?php

namespace Fold\PhpTools\RSA;

class RSA
{

    /**
     * RSA-SHA256 签名
     */
    public function rsaSign(string $data, string $privateKey): string
    {
        $keyResource = openssl_pkey_get_private($privateKey);
        if (!$keyResource) {
            throw new RuntimeException("无效私钥: " . openssl_error_string());
        }

        $signature = '';
        $result = openssl_sign($data, $signature, $keyResource, OPENSSL_ALGO_SHA256);
        if (!$result) {
            throw new RuntimeException("签名失败: " . openssl_error_string());
        }

        return bin2hex($signature);
    }

    /**
     * RSA-SHA256 签名验证
     */
    public function rsaVerify(string $data, string $signature, string $publicKey): bool
    {
        $keyResource = openssl_pkey_get_public($publicKey);
        if (!$keyResource) {
            return false;
        }

        return openssl_verify($data, hex2bin($signature), $keyResource, OPENSSL_ALGO_SHA256) === 1;
    }
}
