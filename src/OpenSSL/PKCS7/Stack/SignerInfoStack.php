<?php


namespace Cijber\OpenSSL\PKCS7\Stack;

use Cijber\OpenSSL\PKCS7\SignerInfo;
use Cijber\OpenSSL\Stack;
use FFI\CData;

class SignerInfoStack extends Stack
{
    protected function spawn(CData $cData): SignerInfo
    {
        // TODO: Implement spawn() method.
    }
}
