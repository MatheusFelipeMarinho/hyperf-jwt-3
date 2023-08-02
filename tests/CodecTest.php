<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfTest;

use Exception;
use HyperfExt\Jwt\Codec;
use HyperfExt\Jwt\Exceptions\JwtException;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;
use InvalidArgumentException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validator;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @internal
 * @coversNothing
 */
class CodecTest extends AbstractTestCase
{
    /**
     * @var MockInterface
     */
    protected MockInterface $parser;

    /**
     * @var MockInterface
     */
    protected MockInterface $builder;

    /**
     * @var MockInterface
     */
    protected MockInterface $validator;

    public function setUp(): void
    {
        parent::setUp();

        $this->builder = Mockery::mock(Builder::class);
        $this->parser = Mockery::mock(Parser::class);
        $this->validator = Mockery::mock(Validator::class);
    }

    /** @test */
    public function itShouldSetTheAlgo()
    {
        $codec = $this->getCodec('secret', 'HS256', []);
        $codec->setAlgo('HS512');

        $this->assertSame('HS512', $codec->getAlgo());
    }

    /** @test */
    public function itShouldSetTheSecret()
    {
        $codec = $this->getCodec('secret', 'HS256', []);
        $codec->setSecret('foo');

        $this->assertSame('foo', $codec->getSecret());
    }

    /** @test */
    public function itShouldReturnTheTokenWhenPassingAValidPayloadToEncode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $dataSet = new DataSet($payload, 'payload');

        $this->builder->shouldReceive('relatedTo')->once()->andReturnSelf(); // sub
        $this->builder->shouldReceive('expiresAt')->once()->andReturnSelf(); // exp
        $this->builder->shouldReceive('issuedAt')->once()->andReturnSelf();  // iat
        $this->builder->shouldReceive('issuedBy')->once()->andReturnSelf();  // iss
        $this->builder
            ->shouldReceive('getToken')
            ->once()
            ->with(\Mockery::type(Signer::class), \Mockery::type(Key::class))
            ->andReturn(new Token\Plain(new DataSet([], 'header'), $dataSet, (new Token\Signature('', 'signature'))));

        /** @var Token $token */
        $token = $this->getCodec('secret', 'HS256')->encode($payload);

        $this->assertSame('header.payload.signature', $token);
    }

    /** @test */
    public function itShouldThrowAnInvalidExceptionWhenThePayloadCouldNotBeEncoded()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('Could not create token:');

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->builder->shouldReceive('relatedTo')->once()->andReturnSelf(); // sub
        $this->builder->shouldReceive('expiresAt')->once()->andReturnSelf(); // exp
        $this->builder->shouldReceive('issuedAt')->once()->andReturnSelf();  // iat
        $this->builder->shouldReceive('issuedBy')->once()->andReturnSelf();  // iss
        $this->builder
            ->shouldReceive('getToken')
            ->once()
            ->with(\Mockery::type(Signer::class), \Mockery::type(Key::class))
            ->andThrow(new Exception());

        $this->getCodec('secret', 'HS256')->encode($payload);
    }

    /** @test */
    public function itShouldReturnThePayloadWhenPassingAValidTokenToDecode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $token = Mockery::mock(Token::class);
        $dataSet = Mockery::mock(new DataSet($payload, 'payload'));

        $codec = $this->getCodec('secret', 'HS256');

        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andReturn($token);
        $this->validator->shouldReceive('validate')->once()->with($token, Mockery::any())->andReturnTrue();
        $token->shouldReceive('claims')->once()->andReturn($dataSet);
        $dataSet->shouldReceive('all')->once()->andReturn($payload);

        $this->assertSame($payload, $codec->decode('foo.bar.baz'));
    }

    /** @test */
    public function itShouldThrowATokenInvalidExceptionWhenTheTokenCouldNotBeDecodedDueToABadSignature()
    {
        $token = Mockery::mock(Token::class);
        $dataSet = Mockery::mock(new DataSet(['pay', 'load'], 'payload'));

        $codec = $this->getCodec('secret', 'HS256');

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token Signature could not be verified.');

        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andReturn($token);
        $this->validator->shouldReceive('validate')->once()->with($token, Mockery::any())->andReturnFalse();
        $token->shouldReceive('claims')->never();
        $dataSet->shouldReceive('all')->never();

        $codec->decode('foo.bar.baz');
    }

    /** @test */
    public function itShouldThrowATokenInvalidExceptionWhenTheTokenCouldNotBeDecoded()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Could not decode token:');

        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andThrow(new InvalidArgumentException());
        $this->parser->shouldReceive('verify')->never();
        $this->parser->shouldReceive('getClaims')->never();

        $this->getCodec('secret', 'HS256')->decode('foo.bar.baz');
    }

    /** @test */
    public function itShouldGenerateATokenWhenUsingAnRsaAlgorithm()
    {
        $dummyPrivateKey = $this->getDummyPrivateKey();
        $dummyPublicKey = $this->getDummyPublicKey();

        $codec = $this->getCodec(
            'does_not_matter',
            'RS256',
            ['private' => $dummyPrivateKey, 'public' => $dummyPublicKey]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $dataSet = new DataSet($payload, 'payload');

        $this->builder->shouldReceive('relatedTo')->once()->andReturnSelf(); // sub
        $this->builder->shouldReceive('expiresAt')->once()->andReturnSelf(); // exp
        $this->builder->shouldReceive('issuedAt')->once()->andReturnSelf();  // iat
        $this->builder->shouldReceive('issuedBy')->once()->andReturnSelf();  // iss
        $this->builder
            ->shouldReceive('getToken')
            ->once()
            ->with(Mockery::type(RS256::class), Mockery::type(Key::class))
            ->andReturn(new Token\Plain(new DataSet([], 'header'), $dataSet, (new Token\Signature('', 'signature'))));

        $token = $codec->encode($payload);

        $this->assertSame('header.payload.signature', $token);
    }

    /** @test */
    public function itShouldThrowAExceptionWhenTheAlgorithmPassedIsInvalid()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('The given algorithm could not be found');

        $this->parser->shouldReceive('parse')->never();
        $this->parser->shouldReceive('verify')->never();

        $this->getCodec('secret', 'AlgorithmWrong')->decode('foo.bar.baz');
    }

    /**
     * @test
     */
    public function itShouldReturnThePublicKey()
    {
        $codec = $this->getCodec(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys['public'], $codec->getPublicKey());
    }

    /**
     * @test
     */
    public function itShouldReturnTheKeys()
    {
        $codec = $this->getCodec(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys, $codec->getKeys());
    }

    /**
     * @param       $secret
     * @param       $algo
     * @param array $keys
     * @return Codec|MockObject
     * @throws
     */
    public function getCodec($secret, $algo, array $keys = []): Codec|MockObject
    {
        $codec = new Codec($secret, $algo, $keys);
        $config = Mockery::mock($codec->getConfig());

        $codec = new Codec($secret, $algo, $keys, $config);

        $config->shouldReceive('builder')->andReturn($this->builder);
        $config->shouldReceive('parser')->andReturn($this->parser);
        $config->shouldReceive('validator')->andReturn($this->validator);

        $constraint = Mockery::mock(Constraint::class);
        $constraint->shouldReceive('assert')->andReturn();
        $config->shouldReceive('validationConstraints')->andReturn([$constraint]);

        return $codec;
    }

    public function getDummyPrivateKey(): false|string
    {
        return file_get_contents(__DIR__ . '/Keys/id_rsa');
    }

    public function getDummyPublicKey(): false|string
    {
        return file_get_contents(__DIR__ . '/Keys/id_rsa.pub');
    }
}
