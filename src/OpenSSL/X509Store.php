<?php


namespace Cijber\OpenSSL;


use Cijber\OpenSSL;
use Cijber\OpenSSL\C\CBackedObjectWithOwner;

class X509Store extends CBackedObjectWithOwner
{
    public static function new(): X509Store
    {
        $ffi = OpenSSL::getFFI();
        $x509 = $ffi->X509_STORE_new();
        return new X509Store($ffi, $x509);
    }

    public function freeObject()
    {
        $this->ffi->X509_STORE_free($this->cObj);
    }
}