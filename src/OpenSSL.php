<?php


namespace Cijber;

use Cijber\OpenSSL\Instance;
use FFI;

/**
 * Class OpenSSL
 * @package Cijber
 */
class OpenSSL
{
    private static ?Instance $instance = null;
    private static ?FFI $stdLib = null;

    /**
     * Get an OpenSSL instance which holds the FFI object,
     * And initializes OpenSSL and frees when destructed
     *
     * @return Instance
     */
    public static function getInstance(): Instance
    {
        if (static::$instance === null) {
            static::$instance = new Instance();
            static::$instance->init();
        }

        return static::$instance;
    }

    public static function getFFI(): FFI
    {
        return static::getInstance()->getFFI();
    }

    public static function getStdLib(): FFI
    {
        if (static::$stdLib === null) {
            static::$stdLib = FFI::cdef("void* malloc (size_t size);", "libc.so.6");
        }

        return static::$stdLib;
    }

    public static function malloc(int $size): FFI\CData
    {
        return static::getStdLib()->malloc($size);
    }
}
