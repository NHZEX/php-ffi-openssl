<?php


namespace Cijber\OpenSSL\Tests;


use Cijber\OpenSSL;
use Cijber\OpenSSL\Stack;
use Cijber\OpenSSL\X509;
use PHPStan\Testing\TestCase;

class StackTest extends TestCase
{
    function testCreationAndDestruction()
    {
        $stack = Stack\X509Stack::new();
        $this->assertCount(0, $stack);
    }

    function testPush()
    {
        $stack = Stack\X509Stack::new();
        $x509 = X509::new();
        $stack->push($x509);
        $this->assertCount(1, $stack);
        $x509Item = $stack->get(0);
        $this->assertNotSame($x509, $x509Item);
    }

    function testSet()
    {
        $stack = Stack\X509Stack::new();
        $a = X509::new();
        $b = X509::new();

        $stack->push($a);
        $stack->set(0, $b);
        $this->assertNotSame($a, $stack->get(0));
        $this->assertCount(1, $stack);
        $this->assertEquals(0, $a->getRefCount());
    }

    function testDelete()
    {
        $stack = Stack\X509Stack::new();
        $a = X509::new();
        $c = X509::new();
        $stack->push($a);
        $stack->push($c);
        $b = $stack->delete(0);
        $this->assertCount(1, $stack);
        unset($stack[0]);
        $this->assertCount(0, $stack);

        $this->expectException(\RuntimeException::class);
        $stack->delete(1);
    }

    function testRetention()
    {
        $stack = Stack\X509Stack::new();
        $x509 = X509::new();
        $stack->push($x509);
        $this->assertCount(1, $stack);
        $x509Item = $stack->get(0);
        unset($x509Item, $x509);

        /** @var X509 $x509 */
        $x509 = $stack->get(0);
        $stack->freeAll();
        $this->assertTrue($stack->isFreed());
        $this->assertFalse($x509->isFreed());
    }

    function testAddressingCorrect()
    {
        $ffi = OpenSSL::getFFI();
        $x509 = $ffi->X509_new();
        $address = OpenSSL::addressOf($x509);
        $st = $ffi->sk_new_null();
        $ffi->sk_push($st, $x509);
        $second = $ffi->cast("X509*", $ffi->sk_value($st, 0));
        $secondAddress = OpenSSL::addressOf($second);
        $this->assertEquals($address, $secondAddress);
    }

    function testForeach()
    {
        $stack = Stack\X509Stack::new();
        $a = X509::new();
        $b = X509::new();
        $c = X509::new();
        $stack->push($a);
        $stack->push($b);
        $stack->push($c);

        $x = 0;
        foreach ($stack as $x509) {
            $x++;
            $this->assertEquals(X509::class, get_class($x509));
        }

    }

    function testPop()
    {
        $stack = Stack\X509Stack::new();
        $a = X509::new();
        $b = X509::new();
        $c = X509::new();
        $stack->push($a);
        $stack->push($b);
        $stack[] = $c;

        $i = 0;
        while ($x509 = $stack->pop()) {
            $this->assertEquals(X509::class, get_class($x509));
            $i++;
        }

        $this->assertEquals(3, $i);
    }
}