<?php


namespace Cijber\OpenSSL\C;

use FFI;
use FFI\CData;

class CBackedObject
{
    const TYPE = "void*";

    protected CData $cObj;
    protected bool $managed = true;
    protected int $refCount = 0;
    protected bool $freed = false;

    /**
     * CBackedObject constructor.
     * @param CData $cObj
     * @param bool $managed
     */
    protected function __construct(CData $cObj, bool $managed = true)
    {
        $this->cObj = $cObj;
        $this->managed = $managed;
    }

    /**
     * Mark backing C object as freed
     */
    public function freed()
    {
        $this->freed = true;
    }

    public function isFreed(): bool
    {
        return $this->freed;
    }

    public function ensureNotFreed()
    {
        if ($this->isFreed()) {
            throw new \RuntimeException("object " . get_class($this) . " already freed, can't be used");
        }
    }

    /**
     * Free backing C object, object is useless after this operation
     */
    final public function free(): bool
    {
        if ($this->freed || (!$this->managed || $this->refCount > 0)) {
            return false;
        }

        $this->freeObject();
        $this->freed();
        return true;
    }

    protected function freeObject()
    {
        FFI::free($this->cObj);
    }

    public function __destruct()
    {
        $this->free();
    }

    public function unmanaged()
    {
        $this->managed = false;
    }

    public function pushRefCount()
    {
        $this->refCount++;
    }

    public function decreaseRefCount()
    {
        $this->refCount--;
    }

    public function getRefCount()
    {
        return $this->refCount;
    }

    public function managed()
    {
        $this->managed = true;
    }
}
