<?php


namespace Cijber\OpenSSL;

use Cijber\OpenSSL;
use Cijber\OpenSSL\C\CBackedObjectWithOwner;

class X509 extends CBackedObjectWithOwner
{
    const TYPE = "X509*";

    public static function new(): X509
    {
        $ffi = OpenSSL::getFFI();
        $x509 = $ffi->X509_new();
        return new X509($ffi, $x509);
    }

    public function freeObject()
    {
        $this->ffi->X509_free($this->cObj);
    }
}
