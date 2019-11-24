<?php


namespace Cijber\OpenSSL\Tests;


use Cijber\OpenSSL\BIO;
use PHPUnit\Framework\TestCase;

class BIOTest extends TestCase
{
    public function testCreationAndDestruction()
    {
        $bio = BIO::new();
        $this->assertEquals(11, $bio->write("Hello world"));
        $this->assertEquals("Hello world", $bio->read());
        $bio->write("Hello world");
        $bio->reset();
        $this->assertEquals('', $bio->read());
    }

    public function testOpen()
    {
        $bio = BIO::open(__DIR__ . "/data/pkcs7/1.SF", "r");
        $part = $bio->read(5);
        $this->assertEquals("Signa", $part);
        $this->assertEquals(5, $bio->tell());
        $bio->seek(6);
        $this->assertEquals(6, $bio->tell());
        $part = $bio->read(3);
        $this->assertEquals("ure", $part);
        $bio->reset();
        $this->assertEquals(0, $bio->tell());
    }

    public function testBuffer()
    {
        $bio = BIO::buffer("Hello world");
        $this->assertEquals("Hello world", $bio->read());
        $this->assertTrue($bio->eof());
        $bio->reset();
        $part = $bio->read(3);
        $this->assertEquals("Hel", $part);
        $this->assertEquals("lo", $bio->read(2));
        $bio->reset();
        $part = $bio->read(3);
        $this->assertEquals("Hel", $part);
    }
}