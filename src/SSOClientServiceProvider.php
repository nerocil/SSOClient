<?php

namespace SSOClient\SSOClient;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use SSOClient\SSOClient\Commands\SSOClientCommand;

class SSOClientServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('ssoclient')
            ->hasConfigFile()
            ->hasViews()
            ->hasMigration('create_ssoclient_table')
            ->hasCommand(SSOClientCommand::class);
    }

    public function register(): void
    {
        $this->app->singleton(SSOClient::class, function ($app) {
            return new SSOClient();
        });
    }

    public function boot():void
    {
        $this->publishes([
            __DIR__.'/../config/ssoclient.php' => config_path('ssoclient.php'),
        ], 'sso-config');
    }
}
