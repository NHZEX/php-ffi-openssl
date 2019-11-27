<?php


namespace Cijber\OpenSSL;

use Cijber\OpenSSL;
use Cijber\OpenSSL\C\Memory;
use FFI;
use RuntimeException;

class PKCS7 extends OpenSSL\C\CBackedObjectWithOwner
{
    const TYPE = "PKCS7*";

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

    public function toSigned(): PKCS7\Signed
    {
        $this->ensureNotFreed();

        if ($this->getType() !== self::NID_SIGNED) {
            throw new RuntimeException("This PKCS7 isn't of type signed");
        }

        return new PKCS7\Signed($this);
    }

    /**
     * Returns a DER representation of this PKCS7
     *
     * @return string
     */
    public function toDER(): string
    {
        $this->ensureNotFreed();

        // Create NULL uint8_t*
        $buf = $this->ffi->new("uint8_t*");
        // Get pointer from it (ptr being now uint8_t**)
        $ptr = FFI::addr($buf);
        // Give NULL pointer to OpenSSL and let it fill it up
        $len = $this->ffi->i2d_PKCS7($this->cObj, $ptr);
        if ($len < 0) {
            throw new RuntimeException("Failed to create DER from PKCS7 object");
        }

        // Read string from pointer
        $val = FFI::string($buf, $len);
        // Free buffer via CRYPTO_free as OpenSSL malloc'd it
        $this->ffi->CRYPTO_free($buf);

        return $val;
    }

    /**
     * @inheritDoc
     */
    public function freeObject()
    {
        $this->ffi->PKCS7_free($this->cObj);
    }

    /**
     * Create new PKCS7
     *
     * @return PKCS7
     */
    public static function new(): PKCS7
    {
        $ffi = OpenSSL::getFFI();
        $cObj = $ffi->PKCS7_new();
        return new PKCS7($ffi, $cObj);
    }

    /**
     * Load a PKCS7 object from DER
     *
     * @param string $der The string containing the DER
     * @return PKCS7
     */
    public static function loadFromDER(string $der): PKCS7
    {
        $ffi = OpenSSL::getFFI();
        $derLen = strlen($der);
        $mem = Memory::buffer($der);
        $res = $ffi->d2i_PKCS7(null, $mem->pointer(), $derLen);

        if ($res === null) {
            throw new RuntimeException("Failed loading DER");
        }

        $mem->freed();
        return static::cast($ffi, $res);
    }
}
