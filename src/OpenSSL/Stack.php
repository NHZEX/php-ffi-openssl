<?php


namespace Cijber\OpenSSL;

use ArrayAccess;
use Cijber\OpenSSL;
use Cijber\OpenSSL\C\CBackedObject;
use Cijber\OpenSSL\C\CBackedObjectWithOwner;
use Countable;
use FFI\CData;
use InvalidArgumentException;
use IteratorAggregate;
use RuntimeException;
use Traversable;

/**
 * Class Stack
 * @package Cijber\OpenSSL
 */
abstract class Stack extends CBackedObjectWithOwner implements Countable, ArrayAccess, Traversable, IteratorAggregate
{
    const CLASSNAME = CBackedObjectWithOwner::class;

    abstract protected function spawn(CData $cData);

    public static function new()
    {
        $ffi = OpenSSL::getFFI();
        $cObj = $ffi->sk_new_null();
        return new static($ffi, $cObj);
    }

    protected function freeObject()
    {
        $this->ffi->sk_free($this->cObj);
    }

    public function count(): int
    {
        return $this->ffi->sk_num($this->cObj);
    }

    public function get(int $offset)
    {
        $res = $this->ffi->sk_value($this->cObj, $offset);

        if ($res === null) {
            throw new RuntimeException("Failed to retrieve item from stack");
        }

        return $this->spawn($res);
    }

    public function set(int $offset, CBackedObject $object): void
    {
        /***
         * Make sure ref count is updated for old object
         */
        /** @var CBackedObjectWithOwner $obj */
        $obj = $this->get($offset);
        $res = $this->ffi->sk_set($this->cObj, $offset, $object->cObj);

        if ($res === null) {
            throw new RuntimeException("Failed to set item on stack");
        }

        $obj->decreaseRefCount();
    }

    public function shift()
    {
        $cObj = $this->ffi->sk_shift($this->cObj);
        return $this->handleResult($cObj);
    }

    protected function handleResult(?CData $cObj)
    {
        if ($cObj === null) {
            return null;
        }

        /** @var CBackedObjectWithOwner $obj */
        $obj = $this->spawn($cObj);
        $obj->decreaseRefCount();
        return $obj;
    }

    public function pop()
    {
        $cObj = $this->ffi->sk_pop($this->cObj);
        return $this->handleResult($cObj);
    }

    public function push(CBackedObject $object): int
    {
        $this->ensureCorrect($object);
        $idx = $this->ffi->sk_push($this->cObj, $object->cObj);
        if ($idx === 0) {
            throw new RuntimeException("Failed to insert element");
        }

        $object->pushRefCount();

        return $idx;
    }

    private function ensureCorrect($object)
    {
        $expectedClassName = static::CLASSNAME;

        if (!($object instanceof $expectedClassName)) {
            throw new InvalidArgumentException("Expected object of class $expectedClassName got object of class " . get_class($object));
        }
    }

    public function unshift(CBackedObject $object): int
    {
        $this->ensureCorrect($object);

        $idx = $this->ffi->sk_unshift($this->cObj, $object->cObj);
        if ($idx === 0) {
            throw new RuntimeException("Failed to insert element");
        }

        $object->pushRefCount();

        return $idx;
    }

    public function freeAll()
    {
        $this->ffi->sk_pop_free($this->cObj, function (CData $cObj) {
            /** @var CBackedObject $cObj */
            $cObj = $this->spawn($cObj);
            $cObj->decreaseRefCount();
            $cObj->free();
        });

        $this->freed();
    }

    public function offsetExists($offset)
    {
        return $offset >= 0 && $offset < $this->count();
    }

    public function offsetGet($offset)
    {
        return $this->get($offset);
    }

    public function offsetSet($offset, $value)
    {
        if ($offset === null) {
            $this->push($value);
            return;
        }

        $this->set($offset, $value);
    }

    public function offsetUnset($offset)
    {
        return $this->delete($offset);
    }

    public function delete($offset)
    {
        $obj = $this->ffi->sk_delete($this->cObj, $offset);
        if ($obj === null) {
            throw new RuntimeException("Failed to delete element $offset from stack");
        }

        /** @var CBackedObjectWithOwner $phpObj */
        $phpObj = $this->spawn($obj);
        $phpObj->decreaseRefCount();

        return $phpObj;
    }

    public function getIterator()
    {
        for ($i = 0; $i < $this->count(); $i++) {
            yield $this[$i];
        }
    }

    public function __clone()
    {
        $cObj = $this->ffi->sk_dup($this->cObj);

        if ($cObj === null) {
            throw new RuntimeException("Failed to clone stack");
        }

        /** @var CBackedObjectWithOwner $obj */
        foreach ($this as $obj) {
            $obj->pushRefCount();
        }

        return new static($this->ffi, $cObj);
    }
}
