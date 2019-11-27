<?php


namespace Cijber\OpenSSL\Stack;

use Cijber\OpenSSL\Stack;
use Cijber\OpenSSL\X509;
use FFI;
use FFI\CData;

class X509Stack extends Stack
{
    const CLASSNAME = X509::class;

    public static function from(FFI $ffi, CData $cObj): X509Stack
    {
        return new X509Stack($ffi, $cObj);
    }

    public function spawn(CData $cData): X509
    {
        return X509::cast($this->ffi, $cData);
    }
}
