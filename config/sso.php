<?php

// config for SSOClient/SSOClient
return [
    // SSO Authentication Server URL
    'auth_server_url' => env('SSO_AUTH_SERVER_URL', 'http://app1.local'),

    // Application slug for identification
    'app_slug' => env('SSO_APP_SLUG'),

    // Secret key for app verification
    'secret_key' => env('SSO_SECRET_KEY'),

    // Token cache duration in minutes
    'token_cache_duration' => env('SSO_TOKEN_CACHE_DURATION', 300),

    // Validation cache duration in minutes
    'validation_cache_duration' => env('SSO_VALIDATION_CACHE_DURATION', 300),

    // Allow token via query parameter (less secure)
    'allow_query_token' => env('SSO_ALLOW_QUERY_TOKEN', false),

    // Login route name for redirects
    'login_route' => env('SSO_LOGIN_ROUTE', 'login'),

    // Default guard for SSO
    'default_guard' => env('SSO_DEFAULT_GUARD', 'sso'),

    // Token refresh threshold in minutes
    'refresh_threshold' => env('SSO_REFRESH_THRESHOLD', 10),

    // HTTP timeout for SSO requests
    'timeout' => env('SSO_HTTP_TIMEOUT', 30),

    // Retry configuration
    'retry_attempts' => env('SSO_RETRY_ATTEMPTS', 3),
    'retry_delay' => env('SSO_RETRY_DELAY', 1000), // milliseconds
];
