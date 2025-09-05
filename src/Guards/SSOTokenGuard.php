<?php

namespace SSOClient\SSOClient\Guards;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use SSOClient\SSOClient\Services\SSOAuthService;

class SSOTokenGuard implements Guard, StatefulGuard
{
    protected $request;

    protected $provider;

    protected $ssoService;

    protected $user;

    protected $name;

    public function __construct(
        $name,
        UserProvider $provider,
        Request $request,
        SSOAuthService $ssoService
    ) {
        $this->name = $name;
        $this->provider = $provider;
        $this->request = $request;
        $this->ssoService = $ssoService;
    }

    public function check()
    {
        return ! is_null($this->user());
    }

    public function guest()
    {
        return ! $this->check();
    }

    public function user()
    {
        // Return cached user if already resolved
        if ($this->user !== null) {
            return $this->user;
        }

        // Try to get token from multiple sources
        $token = $this->getTokenFromRequest();

        if (! $token) {
            return null;
        }

        // Find user by token
        $userModel = config('auth.providers.users.model', 'App\Models\User');
        $user = $userModel::where('sso_token', $token)->first();

        if (! $user) {
            Log::debug('No user found with SSO token');

            return null;
        }

        // Validate token with App1
        if (! $this->ssoService->validateUserToken($user)) {
            Log::info("Invalid SSO token for user {$user->id}, attempting refresh");

            // Try to refresh token
            if (! $this->ssoService->refreshUserToken($user)) {
                Log::warning("Failed to refresh token for user {$user->id}");

                return null;
            }
        }

        return $this->user = $user;
    }

    public function id()
    {
        $user = $this->user();

        return $user ? $user->getAuthIdentifier() : null;
    }

    public function validate(array $credentials = [])
    {
        if (empty($credentials['email']) || empty($credentials['password'])) {
            return false;
        }

        return $this->ssoService->loginUser(
            $credentials['email'],
            $credentials['password']
        ) !== false;
    }

    public function hasUser()
    {
        return ! is_null($this->user);
    }

    public function setUser($user)
    {
        $this->user = $user;

        return $this;
    }

    // StatefulGuard interface methods
    public function attempt(array $credentials = [], $remember = false)
    {
        $user = $this->ssoService->loginUser(
            $credentials['email'] ?? '',
            $credentials['password'] ?? ''
        );

        if ($user) {
            $this->login($user, $remember);

            return true;
        }

        return false;
    }

    public function once(array $credentials = [])
    {
        $user = $this->ssoService->loginUser(
            $credentials['email'] ?? '',
            $credentials['password'] ?? ''
        );

        if ($user) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    public function login($user, $remember = false)
    {
        // Set the user in the guard
        $this->setUser($user);

        // Store token in session for persistence
        if ($user->sso_token) {
            $this->request->session()->put('sso_token', $user->sso_token);

            if ($remember) {
                // Set a longer-lived cookie for "remember me"
                cookie()->queue(
                    'sso_token',
                    $user->sso_token,
                    config('sso.remember_duration', 43200) // 30 days default
                );
            }
        }

        Log::info("User {$user->id} logged in via SSO guard");
    }

    public function loginUsingId($id, $remember = false)
    {
        $userModel = config('auth.providers.users.model', 'App\Models\User');
        $user = $userModel::find($id);

        if ($user && $user->sso_token) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    public function onceUsingId($id)
    {
        $userModel = config('auth.providers.users.model', 'App\Models\User');
        $user = $userModel::find($id);

        if ($user && $user->sso_token) {
            $this->setUser($user);

            return $user;
        }

        return false;
    }

    public function viaRemember()
    {
        // Check if user was logged in via "remember me"
        $token = $this->request->cookie('sso_token');

        return ! empty($token) && $this->user();
    }

    public function logout()
    {
        if ($this->user) {
            $this->ssoService->logoutUser($this->user);
        }

        // Clear session and cookies
        $this->request->session()->forget('sso_token');
        cookie()->queue(cookie()->forget('sso_token'));

        $this->user = null;

        Log::info('User logged out from SSO guard');
    }

    /**
     * Get token from various request sources
     */
    protected function getTokenFromRequest()
    {
        // 1. Check Authorization header (Bearer token)
        $token = $this->request->bearerToken();
        if ($token) {
            return $token;
        }

        // 2. Check session
        $token = $this->request->session()->get('sso_token');
        if ($token) {
            return $token;
        }

        // 3. Check cookie
        $token = $this->request->cookie('sso_token');
        if ($token) {
            return $token;
        }

        // 4. Check query parameter (less secure, use cautiously)
        if (config('sso.allow_query_token', false)) {
            $token = $this->request->query('token');
            if ($token) {
                return $token;
            }
        }

        return null;
    }

    /**
     * Get the name of the guard
     */
    public function getName()
    {
        return $this->name;
    }
}
