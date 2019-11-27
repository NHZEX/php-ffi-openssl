<?php


namespace Cijber\OpenSSL\C;

use Cijber\OpenSSL;
use Cijber\OpenSSL\FFIWrapper;
use FFI;
use FFI\CData;

class CBackedObjectWithOwner extends CBackedObject
{
    private static array $known = [];
    private int $address = -1;

    protected FFI $ffi;

    protected function __construct(FFI $ffi, CData $cObj)
    {
        parent::__construct($cObj);
        $x = FFI::cast("long long", $cObj);
        $this->address = $x->cdata;
        $this->ffi = $ffi;
        static::$known[$this->address] = $this;
    }

    public function freed()
    {
        unset(static::$known[$this->address]);
        parent::freed();
    }

    /**
     * Cast an CData as
     *
     * @param FFI $ffi
     * @param CData $cData
     * @return static
     * @internal
     */
    public static function cast(FFI $ffi, CData $cData)
    {
        /**
         * Cast first, so it acts like a pointer
         */
        $casted = $ffi->cast(static::TYPE, $cData);
        $address = OpenSSL::addressOf($casted);
        if (array_key_exists($address, static::$known)) {
            return static::$known[$address];
        }

        return new static($ffi, $casted);
    }
}
