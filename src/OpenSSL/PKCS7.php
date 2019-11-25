<?php


namespace Cijber\OpenSSL;


use Cijber\OpenSSL;
use Cijber\OpenSSL\C\Memory;
use FFI;

class PKCS7 extends OpenSSL\C\CBackedObjectWithOwner
{
    /**
     * NID_pkcs7
     */
    const NID = 20;
    const NID_DATA = 21;
    const NID_SIGNED = 22;
    const NID_ENVELOPED = 23;
    const NID_SIGNED_AND_ENVELOPED = 24;
    const NID_DIGEST = 25;
    const NID_ENCRYPTED = 26;

    /**
     * Verify with NID_ consts defined in Cijber\OpenSSL\PKCS7
     * @return int
     */
    public function getType(): int
    {
        return $this->ffi->OBJ_obj2nid($this->cObj->type);
    }

    public function verify(string $plain): bool
    {
        $type = $this->getType();
        if (!in_array($type, [PKCS7::NID_DIGEST, self::NID_SIGNED, self::NID_SIGNED_AND_ENVELOPED])) {
            throw new \RuntimeException("Can only verify signed or digested data");
        }
    }

    public function toDER(): string
    {
        $buf = $this->ffi->new("uint8_t*");
        $ptr = FFI::addr($buf);
        $len = $this->ffi->i2d_PKCS7($this->cObj, $ptr);
        if ($len < 0) {
            throw new \RuntimeException("Failed to create DER from PKCS7 object");
        }

        $val = FFI::string($buf, $len);
        $this->ffi->CRYPTO_free($buf);
        return $val;
    }

    public function freeObject()
    {
        $this->ffi->PKCS7_free($this->cObj);
    }

    public static function new(): PKCS7
    {
        $ffi = OpenSSL::getFFI();
        $cObj = $ffi->PKCS7_new();
        return new PKCS7($ffi, $cObj);
    }

    public static function loadFromDER(string $der): PKCS7
    {
        $ffi = OpenSSL::getFFI();
        $derLen = strlen($der);
        $mem = Memory::buffer($der);
        $res = $ffi->d2i_PKCS7(null, $mem->pointer(), $derLen);

        if ($res === null) {
            throw new \RuntimeException("Failed loading DER");
        }

        $mem->freed();
        return new static($ffi, $res);
    }
}