<?php

namespace SSOClient\SSOClient\Commands;

use Illuminate\Console\Command;

class SSOClientCommand extends Command
{
    public $signature = 'ssoclient';

    public $description = 'My command';

    public function handle(): int
    {
        $this->comment('All done');

        return self::SUCCESS;
    }
}
