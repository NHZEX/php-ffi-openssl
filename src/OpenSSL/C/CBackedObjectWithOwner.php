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
}