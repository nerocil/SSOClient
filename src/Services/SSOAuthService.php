<?php

namespace SSOClient\SSOClient\Services;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Carbon\Carbon;
use SSOClient\SSOClient\SSOClient;

class SSOAuthService
{
    protected SSOClient $ssoClient;

    public function __construct(SSOClient $ssoClient)
    {
        $this->ssoClient = $ssoClient;
    }

    public function loginUser($email, $password)
    {
        try {
            $authData = $this->ssoClient->login($email, $password);

            if ($authData) {
                $userModel = config('auth.providers.users.model', 'App\Models\User');

                $user = $userModel::updateOrCreate(
                    ['email' => $authData['user']['email']],
                    [
                        'name' => $authData['user']['name'],
                        'sso_user_id' => $authData['user']['id'],
                        'sso_token' => $authData['token'],
                        'token_expires_at' => $authData['expires_at']
                            ? Carbon::parse($authData['expires_at'])
                            : null,
                        'last_login_at' => now(),
                    ]
                );

                // Store token in session for web guard compatibility
                session(['sso_token' => $authData['token']]);


                Log::info("User {$user->id} logged in via SSO from " . config('sso.app_slug'));
                return $user;
            }
        } catch (\Exception $e) {
            Log::error('SSO login failed: ' . $e->getMessage(), [
                'email' => $email,
                'app_slug' => config('sso.app_slug')
            ]);
        }

        return false;
    }

    public function validateUserToken($user)
    {
        if (!$user || !$user->sso_token) {
            return false;
        }

        // Check if token is expired (if expiration is set)
        if ($user->token_expires_at && now()->gt($user->token_expires_at)) {
            Log::debug("Token expired for user {$user->id}");
            return false;
        }

        // Cache validation results to avoid excessive API calls
        $cacheKey = "sso_validate_{$user->id}_{$user->sso_token}";
        $cacheDuration = config('sso.validation_cache_duration', 300); // 5 minutes default

        return Cache::remember($cacheKey, $cacheDuration, function () use ($user) {
            try {
                $result = $this->ssoClient->validateToken($user->sso_token);
                Log::debug("Token validation result for user {$user->id}: " . ($result ? 'valid' : 'invalid'));
                return $result !== false;
            } catch (\Exception $e) {
                Log::warning('Token validation failed: ' . $e->getMessage(), [
                    'user_id' => $user->id
                ]);
                return false;
            }
        });
    }

    public function refreshUserToken($user):bool
    {
        if (!$user || !$user->sso_token) {
            return false;
        }

        try {
            $newTokenData = $this->ssoClient->refreshToken($user->sso_token);

            if ($newTokenData) {
                $user->update([
                    'sso_token' => $newTokenData['token'],
                    'token_expires_at' => $newTokenData['expires_at']
                        ? Carbon::parse($newTokenData['expires_at'])
                        : null,
                ]);

                // Update session token

                session(['sso_token' => $newTokenData['token']]);


                // Clear validation cache
                Cache::forget("sso_validate_{$user->id}_{$user->sso_token}");

                Log::info("Token refreshed for user {$user->id}");
                return true;
            }
        } catch (\Exception $e) {
            Log::error('Token refresh failed: ' . $e->getMessage(), [
                'user_id' => $user->id
            ]);
        }

        return false;
    }

    public function logoutUser($user = null):void
    {
        $user = $user ?: Auth::user();

        if ($user && $user->sso_token) {
            try {
                $this->ssoClient->logout($user->sso_token);
            } catch (\Exception $e) {
                Log::warning('SSO logout API call failed: ' . $e->getMessage());
            }

            $user->update([
                'sso_token' => null,
                'token_expires_at' => null,
            ]);
        }

        // Clear session and cache

        session()->forget('sso_token');


        if ($user) {
            Cache::forget("sso_validate_{$user->id}_{$user->sso_token}");
        }

        Log::info("User logged out from " . config('sso.app_slug'));
    }

    public function checkUserStatus($user)
    {
        return [
            'is_authenticated' => Auth::check(),
            'has_valid_token' => $user && $this->validateUserToken($user),
            'token_expires_at' => $user->token_expires_at ?? null,
            'needs_refresh' => $user && $user->token_expires_at &&
                now()->addMinutes(10)->gt($user->token_expires_at),
        ];
    }
}
