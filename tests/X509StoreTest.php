<?php


namespace Cijber\OpenSSL\Tests;


use Cijber\OpenSSL\X509Store;
use PHPUnit\Framework\TestCase;

class X509StoreTest extends TestCase
{
    function testCreationAndDestruction()
    {
        $this->expectNotToPerformAssertions();
        X509Store::new();
    }
}