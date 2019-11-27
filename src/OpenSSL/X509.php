<?php


namespace Cijber\OpenSSL;

use Cijber\OpenSSL;
use Cijber\OpenSSL\C\CBackedObjectWithOwner;
use FFI;

class X509 extends CBackedObjectWithOwner
{
    const FILETYPE_DEFAULT = 3;

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

    public function getName()
    {
        return FFI::string($this->cObj->name);
    }

    public function getSHA1Hash()
    {
        $hash = FFI::string($this->cObj->sha1_hash, 20);
        return $hash;
    }
}
