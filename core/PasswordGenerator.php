<?php
namespace core;

use exceptions\PasswordGeneratorException;

class PasswordGenerator
{    
    protected string $symbols = "abcdefghijklmnopqrstuvwxyz"
        . "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        . "1234567890"
        . "!?@#$%^&*)(}{][\"><'`+-/:;=\_|~.,";
    
    protected string $pattern;

    protected int $length = 12;
   
    protected int $bytes = 60;
    
    protected int $cost = 10;
    
    private ?string $_password = null;
    
    private ?string $_salt = null;

    private ?string $_hash = null;    

    public function __construct()
    {        
        $this->pattern = "/"        
            . "(?=.*[a-z])"
            . "(?=.*[A-Z])"
            . "(?=.*[0-9])"
            . "(?=.*[?!*\/\\[\]{}()<>\"'`.,@#$%^&+\-:;=_|~])"
            . "[0-9a-zA-Z?!*\/\\[\]{}()<>\"'`.,@#$%^&+\-:;=_|~]+"
            . "/";      
    }

    public function setLength(int $length): void
    {        
        $this->length = $length;        
    }

    public function setBytes(int $bytes): void
    {
        $this->bytes = $bytes;
    }

    public function setCost(int $cost): void
    {
        $this->cost = $cost;
    }

    public function generate(): void
    {        
        $this->checkLength()->checkBytes()->checkCost();             
        $this->_сreatePassword();
        $this->_createSalt();
        $this->_createHash();
    }

    public function getPassword(): ?string
    {
        return $this->_password;
    }

    public function getSalt(): ?string
    {
        return $this->_salt;
    }

    public function getHash(): ?string
    {
        return $this->_hash;
    }

    public function getPattern(): string
    {
        return $this->pattern;
    }

    public function getSymbols(): string
    {
        return $this->symbols;
    }

    public function verifyPassword(string $password, string $salt, string $hash): bool
    {
        return password_verify($password . $salt, $hash);
    }

    protected function checkLength(): PasswordGenerator
    {
        if ($this->length < 4 || $this->length > 25) {
            throw new PasswordGeneratorException("Length must be between 4 and 25");
        }

        return $this;
    }

    protected function checkBytes(): PasswordGenerator
    {
        if ($this->bytes < 1) {
            throw new PasswordGeneratorException("Length bytes string must be greater than 0");
        }

        return $this;
    }

    protected function checkCost(): PasswordGenerator
    {
        if ($this->cost < 4) {
            throw new PasswordGeneratorException("Bcrypt cost parameter must be greater than 4");
        }

        return $this;
    }
    
    private function _сreatePassword(): void
    {
        while (!preg_match($this->pattern, $this->_password)) {
            $this->_password = null;
            for ($i = 0; $i < $this->length; $i++) {
                $random = rand(0, strlen($this->symbols) - 1);
                $this->_password .= $this->symbols[$random];
            }            
        }        
    }  
    
    private function _createSalt(): void
    {
        $this->_salt = bin2hex(random_bytes($this->bytes));
    }

    private function _createHash(): void
    {
        $this->_hash = password_hash($this->_password . $this->_salt, PASSWORD_BCRYPT, [
            'cost' => $this->cost
        ]);
    }    
}