<?php

namespace SSOClient\SSOClient\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use SSOClient\SSOClient\Services\SSOAuthService;

class EnsureSSOAuthenticated
{
    protected SSOAuthService $ssoService;

    public function __construct(SSOAuthService $ssoService)
    {
        $this->ssoService = $ssoService;
    }

    public function handle(Request $request, Closure $next, ...$guards)
    {
        $guards = empty($guards) ? ['sso'] : $guards;

        foreach ($guards as $guard) {
            if (Auth::guard($guard)->check()) {
                $user = Auth::guard($guard)->user();

                // Additional SSO token validation
                if ($user && isset($user->sso_token)) {
                    if (! $this->ssoService->validateUserToken($user)) {
                        // Try to refresh
                        if (! $this->ssoService->refreshUserToken($user)) {
                            Auth::guard($guard)->logout();

                            if ($request->expectsJson()) {
                                return response()->json(['message' => 'Session expired'], 401);
                            }

                            return $this->redirectToLogin($request);
                        }
                    }
                }

                return $next($request);
            }
        }

        if ($request->expectsJson()) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        return $this->redirectToLogin($request);
    }

    protected function redirectToLogin(Request $request): \Illuminate\Routing\Redirector|\Illuminate\Http\RedirectResponse
    {
        $loginRoute = config('sso.login_route', 'login');

        if (route($loginRoute)) {
            return redirect()->route($loginRoute);
        }

        return redirect('/login');
    }
}
