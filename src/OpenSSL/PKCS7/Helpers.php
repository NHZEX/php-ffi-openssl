<?php


namespace Cijber\OpenSSL\PKCS7;

use Cijber\OpenSSL\PKCS7;

trait Helpers
{
    protected PKCS7 $pkcs7;

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

    public function __construct(PKCS7 $pkcs7)
    {
        $this->pkcs7 = $pkcs7;
    }
}
