<?php


namespace Cijber\OpenSSL\C;

use Cijber\OpenSSL;
use FFI;
use FFI\CData;

class Memory extends CBackedObject
{
    private int $size;

    public function __construct(int $size)
    {
        $this->size = $size;
        parent::__construct(OpenSSL::malloc($size));
    }

    public static function new(int $chunkSize): Memory
    {
        return new Memory($chunkSize);
    }

    public function get(): CData
    {
        $this->ensureNotFreed();

        return $this->cObj;
    }

    public function string(int $length, int $offset = 0)
    {
        $this->ensureNotFreed();

        return substr(FFI::string($this->cObj, $length + $offset), $offset);
    }

    public static function buffer(string $data): Memory
    {
        $len = strlen($data);
        $mem = new Memory($len);
        FFI::memcpy($mem->cObj, $data, $len);
        return $mem;
    }

    public function pointer(): CData
    {
        $this->ensureNotFreed();

        return FFI::addr($this->cObj);
    }
}
