<?php

namespace Cijber\OpenSSL\Tests;

use Cijber\OpenSSL\PKCS7;
use PHPUnit\Framework\TestCase;

class PKCS7Test extends TestCase
{
    public function testCreationAndDestruction()
    {
        $this->expectNotToPerformAssertions();
        $pkcs7 = PKCS7::new();
        unset($pkcs7);
    }

    public function testLoadDER() {
        $der = file_get_contents(__DIR__ . "/data/pkcs7/1.RSA");
        $pkcs7 = PKCS7::loadFromDER($der);
        $this->assertEquals(PKCS7::NID_SIGNED, $pkcs7->getType());
    }
}
