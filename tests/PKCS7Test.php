<?php

namespace Cijber\OpenSSL\Tests;

use Cijber\OpenSSL\PKCS7;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class PKCS7Test extends TestCase
{
    public function testCreationAndDestruction()
    {
        $this->expectNotToPerformAssertions();
        $pkcs7 = PKCS7::new();
        unset($pkcs7);
    }

    public function testLoadDER()
    {
        $der = file_get_contents(__DIR__ . "/data/pkcs7/1.RSA");
        $pkcs7 = PKCS7::loadFromDER($der);
        $newDer = $pkcs7->toDER();
        $this->assertEquals(PKCS7::NID_SIGNED, $pkcs7->getType());
        $this->assertEquals($der, $newDer);
    }

    public function testLoadingGarbageDER()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Failed loading DER");

        PKCS7::loadFromDER("blaat");
    }
}
