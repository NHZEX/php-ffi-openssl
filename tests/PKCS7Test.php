<?php

namespace Cijber\OpenSSL\Tests;

use Cijber\OpenSSL\PKCS7;
use Cijber\OpenSSL\X509;
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
        $signed = $pkcs7->asSigned();
        $certs = $signed->getCerts();
        $this->assertCount(1, $certs);
        /** @var X509 $x509 */
        $x509 = $certs[0];
        $x = $x509->getName();
        $this->assertEquals("/C=US/ST=New York/L=New York/OU=FDroid Repo/O=Guardian Project/CN=guardianproject.info/emailAddress=root@guardianproject.info", $x);
    }

    public function testVerify() {
        $der = file_get_contents(__DIR__ . "/data/pkcs7/1.RSA");
        $plain = file_get_contents(__DIR__ . "/data/pkcs7/1.SF");
        $pkcs7 = PKCS7::loadFromDER($der);
        $signed = $pkcs7->asSigned();
        $result = $signed->verify($plain, PKCS7_NOVERIFY);
        $this->assertTrue($result);
    }

    public function testLoadingGarbageDER()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Failed loading DER");

        PKCS7::loadFromDER("blaat");
    }
}
