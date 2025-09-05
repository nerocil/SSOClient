<?php

namespace SSOClient\SSOClient;

use Illuminate\Support\Facades\Auth;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use SSOClient\SSOClient\Commands\SSOClientCommand;
use SSOClient\SSOClient\Guards\SSOTokenGuard;
use SSOClient\SSOClient\Middleware\EnsureSSOAuthenticated;
use SSOClient\SSOClient\Services\SSOAuthService;

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

    public function register()
    {
        // Register the main SSO client
        $this->app->singleton(SSOClient::class, function ($app) {
            return new SSOClient();
        });

        // Register the SSO auth service
        $this->app->singleton(SSOAuthService::class, function ($app) {
            return new SSOAuthService($app->make(SSOClient::class));
        });

        // Merge package config
        $this->mergeConfigFrom(__DIR__.'/../config/sso.php', 'sso');
    }

    public function boot()
    {
        // Publish configuration
        $this->publishes([
            __DIR__.'/../config/sso.php' => config_path('sso.php'),
        ], 'sso-config');

        // Register the custom guard driver
        $this->registerSSOGuard();

        // Register middleware
        $this->registerMiddleware();

        // Publish migrations if needed
        if ($this->app->runningInConsole()) {
            $this->publishMigrations();
        }
    }

    protected function registerSSOGuard()
    {
        Auth::extend('sso_token', function ($app, $name, array $config) {
            return new SSOTokenGuard(
                $name,
                Auth::createUserProvider($config['provider']),
                $app['request'],
                $app->make(SSOAuthService::class)
            );
        });
    }

    protected function registerMiddleware()
    {
        $router = $this->app['router'];

        $router->aliasMiddleware('sso.auth', EnsureSSOAuthenticated::class);
    }

    protected function publishMigrations()
    {
        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'sso-migrations');
    }

   /* public function register(): void
    {
        $this->app->singleton(SSOClient::class, function ($app) {
            return new SSOClient;
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/sso.php' => config_path('sso.php'),
        ], 'sso-config');
    }*/
}
