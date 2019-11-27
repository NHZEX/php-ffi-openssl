<?php


namespace Cijber\OpenSSL\PKCS7;

use Cijber\OpenSSL\PKCS7;
use FFI;
use FFI\CData;

trait Helpers
{
    protected PKCS7 $pkcs7;
    protected CData $data;
    protected CData $parent;
    protected FFI $ffi;

    public function __construct(PKCS7 $pkcs7, FFI $ffi, CData $data, CData $parent)
    {
        $this->pkcs7 = $pkcs7;
        $this->ffi = $ffi;
        $this->data = $data;
        $this->parent = $parent;
    }

    public static function fromPKCS7(PKCS7 $param, FFI $ffi, CData $data, CData $parent)
    {
        return new static($param, $ffi, $data, $parent);
    }

    public function toDER(): string
    {
        return $this->pkcs7->toDER();
    }

    /**
     * @return PKCS7
     */
    public function getPkcs7(): PKCS7
    {
        return $this->pkcs7;
    }
}
