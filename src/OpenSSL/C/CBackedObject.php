<?php


namespace Cijber\OpenSSL\C;

use FFI;
use FFI\CData;

class CBackedObject
{
    const TYPE = "void*";

    protected CData $cObj;
    protected bool $freed = false;

    /**
     * CBackedObject constructor.
     * @param CData $cObj
     */
    protected function __construct(CData $cObj)
    {
        $this->cObj = $cObj;
    }

    /**
     * Mark backing C object as freed
     */
    public function freed()
    {
        $this->freed = true;
    }

    /**
     * Free backing C object, object is useless after this operation
     */
    final public function free()
    {
        if ($this->freed) {
            return;
        }

        $this->freeObject();
        $this->freed();
    }

    protected function freeObject()
    {
        FFI::free($this->cObj);
    }

    public function __destruct()
    {
        $this->free();
    }
}
