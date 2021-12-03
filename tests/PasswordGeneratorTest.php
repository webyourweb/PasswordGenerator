<?php
namespace test;

use core\PasswordGenerator;
use exceptions\PasswordGeneratorException;
use PHPUnit\Framework\TestCase;

class PasswordGeneratorTest extends TestCase
{
    private PasswordGenerator $_passwordGenerator;    

    protected function setUp(): void
    {
        parent::setUp();
        $this->_passwordGenerator = new PasswordGenerator();
        $this->_passwordGenerator->generate();        
    }

    public function testCheckLength(): void
    {                
        $this->expectException(PasswordGeneratorException::class);
        $this->_passwordGenerator->setLength(3);
        $this->_passwordGenerator->generate();
    }

    public function testCheckBytes(): void
    {        
        $this->expectException(PasswordGeneratorException::class);        
        $this->_passwordGenerator->setBytes(0);        
        $this->_passwordGenerator->generate();
    }

    public function testCheckCost(): void
    {
        $this->expectException(PasswordGeneratorException::class);
        $this->_passwordGenerator->setCost(3);
        $this->_passwordGenerator->generate();
    }

    public function testCreatePassword(): void
    {
        $this->assertRegExp(
            $this->_passwordGenerator->getPattern(), 
            $this->_passwordGenerator->getPassword());
    }

    public function testVerifyPassword(): void
    {
        $this->assertTrue($this->_passwordGenerator->verifyPassword(
            $this->_passwordGenerator->getPassword(),
            $this->_passwordGenerator->getSalt(),
            $this->_passwordGenerator->getHash()
        ));
    }    
}