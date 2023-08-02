<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Claims;

use Hyperf\Context\ApplicationContext;
use Hyperf\Contract\Arrayable;
use Hyperf\Contract\Jsonable;
use HyperfExt\Jwt\Contracts\ClaimInterface;
use HyperfExt\Jwt\Contracts\ManagerInterface;
use JsonSerializable;

abstract class AbstractClaim implements ClaimInterface, Arrayable, Jsonable, JsonSerializable
{
    /**
     * The claim name.
     *
     * @var string
     */
    protected string $name;

    /**
     * The claim value.
     *
     * @var mixed
     */
    private mixed $value;

    /**
     * @var Factory
     */
    private Factory $factory;

    /**
     * @param mixed $value
     */
    public function __construct(mixed $value)
    {
        $this->setValue($value);
    }

    /**
     * Get the payload as a string.
     */
    public function __toString(): string
    {
        return $this->toJson();
    }

    /**
     * Set the claim value, and call a validate method.
     * @param mixed $value
     * @return $this
     */
    public function setValue(mixed $value): static
    {
        $this->value = $this->validateCreate($value);

        return $this;
    }

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue(): mixed
    {
        return $this->value;
    }

    /**
     * Set the claim name.
     *
     * @return $this
     */
    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get the claim name.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Validate the claim in a standalone Claim context.
     * @param mixed $value
     * @return mixed
     */
    public function validateCreate(mixed $value): mixed
    {
        return $value;
    }

    /**
     * Checks if the value matches the claim.
     * @param mixed $value
     * @param bool  $strict
     * @return bool
     */
    public function matches(mixed $value, bool $strict = true): bool
    {
        return $strict ? $this->value === $value : $this->value == $value;
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Build a key value array comprising of the claim name and value.
     */
    public function toArray(): array
    {
        return [$this->getName() => $this->getValue()];
    }

    /**
     * Get the claim as JSON.
     */
    public function toJson(int $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    protected function getFactory(): Factory
    {
        if (! empty($this->factory)) {
            return $this->factory;
        }
        return $this->factory = ApplicationContext::getContainer()->get(ManagerInterface::class)->getClaimFactory();
    }
}
