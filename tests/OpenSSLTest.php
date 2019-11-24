<?php


namespace Cijber\OpenSSL\Tests;


use Cijber\OpenSSL;
use PHPUnit\Framework\TestCase;

class OpenSSLTest extends TestCase
{
    public function testInit()
    {
        $this->expectNotToPerformAssertions();
        OpenSSL::getInstance();
    }
}