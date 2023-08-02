<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */

namespace HyperfExt\Jwt\Storage;

use HyperfExt\Jwt\Contracts\StorageInterface;
use Psr\SimpleCache\CacheInterface;

class HyperfCache implements StorageInterface
{
    /**
     * Constructor.
     */
    public function __construct(protected CacheInterface $cache, protected string $tag)
    {
    }

    public function add(string $key, mixed $value, int $ttl): void
    {
        $this->cache->set($this->resolveKey($key), $value, $ttl);
    }

    public function forever(string $key, mixed $value): void
    {
        $this->cache->set($this->resolveKey($key), $value);
    }

    public function get(string $key): mixed
    {
        return $this->cache->get($this->resolveKey($key));
    }

    public function destroy(string $key): bool
    {
        return $this->cache->delete($this->resolveKey($key));
    }

    public function flush(): void
    {
        method_exists($cache = $this->cache, 'clearPrefix')
            ? $cache->clearPrefix($this->tag)
            : $cache->clear();
    }

    protected function cache(): CacheInterface
    {
        return $this->cache;
    }

    protected function resolveKey(string $key): string
    {
        return $this->tag . '.' . $key;
    }
}
