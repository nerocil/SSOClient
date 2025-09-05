<?php

namespace SSOClient\SSOClient\Guards;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use SSOClient\SSOClient\Services\SSOAuthService;

class SSOTokenGuard implements Guard
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

    public function check():bool
    {
        return !is_null($this->user());
    }

    public function guest():bool
    {
        return !$this->check();
    }

    public function user()
    {
        // Return cached user if already resolved
        if ($this->user !== null) {
            return $this->user;
        }

        // Try to get token from multiple sources
        $token = $this->getTokenFromRequest();

        if (!$token) {
            return null;
        }

        // Find user by token
        $userModel = config('auth.providers.users.model', 'App\Models\User');
        $user = $userModel::where('sso_token', $token)->first();

        if (!$user) {
            Log::debug('No user found with SSO token');
            return null;
        }

        // Validate token with App1
        if (!$this->ssoService->validateUserToken($user)) {
            Log::info("Invalid SSO token for user {$user->id}, attempting refresh");

            // Try to refresh token
            if (!$this->ssoService->refreshUserToken($user)) {
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
        return !is_null($this->user);
    }

    public function setUser($user)
    {
        $this->user = $user;
        return $this;
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

    /**
     * Attempt to authenticate the user
     */
    public function attempt(array $credentials = [], $remember = false)
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

    /**
     * Log the user out
     */
    public function logout()
    {
        if ($this->user) {
            $this->ssoService->logoutUser($this->user);
        }

        $this->user = null;
    }
}
