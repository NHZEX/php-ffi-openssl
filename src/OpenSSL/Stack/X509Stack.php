<?php


namespace Cijber\OpenSSL\Stack;

use Cijber\OpenSSL\Stack;
use Cijber\OpenSSL\X509;
use FFI;
use FFI\CData;

class X509Stack extends Stack
{
    const CLASSNAME = X509::class;

    public static function from(FFI $ffi, CData $cObj, $owner = null): X509Stack
    {
        return new X509Stack($ffi, $cObj, $owner = null);
    }

    public function spawn(CData $cData): X509
    {
        $obj = $this->ffi->cast(X509::TYPE, $cData);
        $clone = $this->ffi->X509_dup($obj);
        if ($clone === null) {
            return X509::new();
        }
        return X509::cast($this->ffi, $clone);
    }
}
