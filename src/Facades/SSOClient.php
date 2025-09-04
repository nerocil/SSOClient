<?php

namespace SSOClient\SSOClient\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \SSOClient\SSOClient\SSOClient
 */
class SSOClient extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \SSOClient\SSOClient\SSOClient::class;
    }
}
