<?php

namespace SSOClient\SSOClient;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;

class SSOClient
{
    protected string $authServerUrl;
    protected string $appSlug;
    protected string $secretKey;

    public function __construct()
    {
        $this->authServerUrl = config('ssoclient.auth_server_url');
        $this->appSlug = config('ssoclient.app_slug');
        $this->secretKey = config('ssoclient.secret_key');
    }

    /**
     * @throws ConnectionException
     */
    public function login($email, $password)
    {
        $response = Http::post("{$this->authServerUrl}/api/sso/login", [
            'email' => $email,
            'password' => $password,
            'app_slug' => $this->appSlug,
        ]);

        if ($response->successful()) {
            $data = $response->json();

            // Cache the token and user data
            $cacheKey = "sso_user_{$data['user']['id']}";
            Cache::put($cacheKey, $data, now()->addMinutes(config('sanctum.expiration', 1440)));

            return $data;
        }

        return false;
    }

    /**
     * @throws ConnectionException
     */
    public function validateToken($token)
    {
        $response = Http::withToken($token)
            ->post("{$this->authServerUrl}/api/sso/validate", [
                'app_slug' => $this->appSlug,
            ]);

        return $response->successful() ? $response->json() : false;
    }

    /**
     * @throws ConnectionException
     */
    public function logout($token): bool
    {
        $response = Http::withToken($token)
            ->post("{$this->authServerUrl}/api/sso/logout");

        return $response->successful();
    }

    /**
     * @throws ConnectionException
     */
    public function refreshToken($token)
    {
        $response = Http::withToken($token)
            ->post("{$this->authServerUrl}/api/sso/refresh", [
                'app_slug' => $this->appSlug,
            ]);

        return $response->successful() ? $response->json() : false;
    }
}
