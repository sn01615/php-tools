<?php

namespace Fold\PhpTools\AES;

class AES256CBC
{

    /**
     * AES-256-CBC 加密
     */
    public function aesEncrypt(string $plaintext, string $key): array
    {
        $method = 'AES-256-CBC';
        $ivLen = openssl_cipher_iv_length($method);
        $iv = openssl_random_pseudo_bytes($ivLen);

        $encrypted = openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new RuntimeException("加密失败: " . openssl_error_string());
        }

        return [
            'iv' => bin2hex($iv),
            'data' => bin2hex($encrypted),
        ];
    }
}
