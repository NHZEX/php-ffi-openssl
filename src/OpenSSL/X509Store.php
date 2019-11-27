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

    public static function default(): X509Store
    {
        $store = X509Store::new();
        $obj = $store->cObj;
        $ffi = $store->ffi;
        $lookup = $ffi->X509_STORE_add_lookup($obj, $ffi->X509_LOOKUP_file());
        if ($lookup === null || !$ffi->X509_LOOKUP_ctrl($lookup, 1, null, X509::FILETYPE_DEFAULT, null)) {
            throw new \RuntimeException("Couldn't load default CA files");
        }

        $lookup = $ffi->X509_STORE_add_lookup($obj, $ffi->X509_LOOKUP_hash_dir());
        if ($lookup === null || !$ffi->X509_LOOKUP_ctrl($lookup, 2, null, X509::FILETYPE_DEFAULT, null)) {
            throw new \RuntimeException("Couldn't load default CA files");
        }

        return $store;
    }

    public function freeObject()
    {
        $this->ffi->X509_STORE_free($this->cObj);
    }
}
