<?php


namespace Cijber\OpenSSL\PKCS7;

use Cijber\OpenSSL;
use Cijber\OpenSSL\BIO;
use Cijber\OpenSSL\Stack\X509Stack;
use Cijber\OpenSSL\X509Store;

class Signed
{
    use Helpers;


    public function getCerts(): X509Stack
    {
        $stack = X509Stack::from($this->ffi, $this->data->cert, $this);
        $stack->unmanaged();
        return $stack;
    }

    public function verify(string $plain, int $flags, ?X509Store $x509Store = null)
    {
        if ($x509Store === null) {
            $x509Store = OpenSSL::CAStore();
        }

        $buffer = BIO::buffer($plain);
        $x = $this->ffi->PKCS7_verify($this->parent, null, $x509Store->getCData(), $buffer->getCData(), null, $flags);
        return $x === 1;
    }
}
