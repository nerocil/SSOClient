<?php

// config for SSOClient/SSOClient
return [
    'auth_server_url' => env('SSO_AUTH_SERVER_URL', 'http://app1.local'),
    'app_slug' => env('SSO_APP_SLUG'),
    'secret_key' => env('SSO_SECRET_KEY'),
    'token_cache_duration' => env('SSO_TOKEN_CACHE_DURATION', 1440),
];
