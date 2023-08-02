<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Contracts;

use HyperfExt\Jwt\Exceptions\InvalidClaimException;

interface ClaimInterface
{
    /**
     * Set the claim value, and call a validate method.
     *
     * @param mixed $value
     *
     * @throws InvalidClaimException
     *
     * @return $this
     */
    public function setValue(mixed $value): static;

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue(): mixed;

    /**
     * Set the claim name.
     *
     * @return $this
     */
    public function setName(string $name): static;

    /**
     * Get the claim name.
     */
    public function getName(): string;

    /**
     * Validate the Claim value.
     */
    public function validate(bool $ignoreExpired = false): bool;
}
