<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            if (! Schema::hasColumn('users', 'sso_user_id')) {
                $table->unsignedBigInteger('sso_user_id')->nullable()->after('id');
            }

            if (! Schema::hasColumn('users', 'sso_token')) {
                $table->text('sso_token')->nullable()->after('password');
            }

            if (! Schema::hasColumn('users', 'token_expires_at')) {
                $table->timestamp('token_expires_at')->nullable()->after('sso_token');
            }

            if (! Schema::hasColumn('users', 'last_login_at')) {
                $table->timestamp('last_login_at')->nullable()->after('updated_at');
            }

            $table->index(['sso_token']);
            $table->index(['sso_user_id']);
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropIndex(['sso_token']);
            $table->dropIndex(['sso_user_id']);
            $table->dropColumn(['sso_user_id', 'sso_token', 'token_expires_at', 'last_login_at']);
        });
    }
};
