<?php


namespace Cijber\OpenSSL\Tests;


use Cijber\OpenSSL\X509;
use PHPUnit\Framework\TestCase;

class X509Test extends TestCase
{
    function testCreationAndDestruction() {
        $this->expectNotToPerformAssertions();
        X509::new();
    }
}