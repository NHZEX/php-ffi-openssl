<?php


namespace Cijber\OpenSSL;


use FFI;

/**
 * Holds instance of the FFI object
 * This class is also responsible for free-ing all global used resources
 * @package Cijber\OpenSSL
 */
class Instance
{
    const HEADERS = [
        "openssl.h",
        "engine.h",
        "generic.h",
        "crypto.h",
        "asn1.h",
        "evp.h",
        "x509.h",
        "pkcs7.h"
    ];

    /**
     * @var FFI
     */
    private ?FFI $ffi = null;


    /**
     * Load FFI object based on header file located in resources/openssl.h
     */
    public function load()
    {
        $code = "";
        $lineCounter = 0;
        $lines = [];

        foreach (static::HEADERS as $header) {
            $lines[$header] = $lineCounter;
            $code .= file_get_contents(__DIR__ . "/../../resources/" . $header);
            $code .= "\n";
            $lineCounter = count(explode("\n", $code));
        }

        $this->ffi = FFI::cdef($code, "libcrypto.so");
    }

    public function init()
    {
        $this->load();
        $ffi = $this->getFFI();
        $ffi->ERR_load_crypto_strings();
        $ffi->OPENSSL_add_all_algorithms_conf();
        $ffi->OPENSSL_config(null);
    }

    public function __destruct()
    {
        if ($this->ffi === null) {
            return;
        }

        $this->ffi->EVP_cleanup();
        $this->ffi->CRYPTO_cleanup_all_ex_data();
        $this->ffi->ERR_free_strings();
    }

    public function getFFI(): FFI
    {
        if ($this->ffi === null) {
            throw new \RuntimeException("Failed to load FFI");
        }

        return $this->ffi;
    }
}