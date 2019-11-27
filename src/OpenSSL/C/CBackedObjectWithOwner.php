<?php


namespace Cijber\OpenSSL\C;

use FFI;
use FFI\CData;

class CBackedObjectWithOwner extends CBackedObject
{
    protected FFI $ffi;

    protected function __construct(FFI $ffi, CData $cObj)
    {
        parent::__construct($cObj);
        $this->ffi = $ffi;
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
        return new static($ffi, FFI::cast(static::TYPE, $cData));
    }
}
