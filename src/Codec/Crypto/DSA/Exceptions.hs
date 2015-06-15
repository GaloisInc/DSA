module Codec.Crypto.DSA.Exceptions(
         -- * Basic DSA Concepts
         ParameterSizes(..)
       , Params(..)
       , PublicKey(..)
       , PrivateKey(..)
       , Signature(..)
       , DSAError(..)
       , getN, getL
         -- * DSA Key generation
       , generateKeyPair
       , generateKeyPairWithParams
         -- * DSA Message Signing
         -- ** Basic, Suggested Mechanisms
       , signMessage
       , verifyMessage
         -- ** Advanced Methods
       , HashFunction(..)
       , signMessage'
       , verifyMessage'
         -- ** /k/ Generation Mechanisms
       , KGenerator
       , KSequence(..)
       , kViaExtraRandomBits
       , kViaTestingCandidates
       , kViaRFC6979
         -- * Generation of /p/ and /q/
         -- ** Generation via the probable primes method
       , ProbablePrimesEvidence(..)
       , generateProbablePrimes
       , validateProbablePrimes
         -- ** Generation via the provable primes method
       , ProvablePrimesEvidence(..)
       , generateProvablePrimes
       , validateProvablePrimes
         -- * Generation of the generator /g/
       , generateUnverifiableGenerator
       , generatorIsValid
       , generateVerifiableGenerator
       , validateVerifiableGenerator
       )
 where

import Codec.Crypto.DSA.Pure(ParameterSizes(..), HashFunction(..),
                             DSAError(..), ProbablePrimesEvidence(..),
                             ProvablePrimesEvidence(..), GenerationEvidence,
                             KGenerator, KSequence(..), getN, getL)
import qualified Codec.Crypto.DSA.Pure as Pure
import Control.Exception
import Crypto.Random
import Crypto.Types.PubKey.DSA
import Data.ByteString.Lazy(ByteString)
import Data.Word

-- |Generate a DSA key pair. This will also generate the /p/, /q/, and /g/
-- parameters using provable and verifiable algorithms, with SHA-256 as the
-- hash function. If you want to use your own /p/, /q/, and /g/ values or 
-- specify your own generation or hash function,, use the
-- 'generateKeyPairWithParams' function, below.
generateKeyPair :: CryptoRandomGen g =>
                   g -> ParameterSizes ->
                   (PublicKey, PrivateKey, ProvablePrimesEvidence, g)
generateKeyPair g s = throwLeft (Pure.generateKeyPair g s)

-- |Generate a key pair given a set of DSA parameters. You really should have
-- validated this set (/p/, /q/, and /g/) using the relevant functions below
-- before you do this. Doing so even if you generated them is probably not a bad
-- practice.
--
-- This uses the method using extra random bits from FIPS 186-4. You better be
-- using a good enough random number generator.
generateKeyPairWithParams :: CryptoRandomGen g =>
                             Params -> g ->
                             (PublicKey, PrivateKey, g)
generateKeyPairWithParams p g =
  throwLeft (Pure.generateKeyPairWithParams p g)

-- |Sign a message using DSA. This method utilizes very good defaults for
-- message signing that should be acceptable for most use cases: it uses SHA-256
-- for the hash function, and generates /k/ using the methods described in RFC
-- 6979. If you wish to change these defaults, please see `signMessaage'`.
signMessage :: PrivateKey -> ByteString -> Signature
signMessage p m = throwLeft (Pure.signMessage p m)

-- |Verify a DSA message signature. This uses the same default mechanisms as
-- `signMessage`.
verifyMessage :: PublicKey -> ByteString -> Signature -> Bool
verifyMessage = Pure.verifyMessage' SHA256

-- |Sign a message given the hash function an /k/ generation routine. Returns
-- either an error the signature generated. You can define your own /k/
-- generation routine ... but we don't recommend it. Actually, while we're
-- recommending, we recommend you use `kViaRFC6979`, if you're not sure
-- which to use.
signMessage' :: CryptoRandomGen g =>
                HashFunction -> KGenerator g -> g ->
                PrivateKey -> ByteString ->
                (Signature, g)
signMessage' h m g p b = throwLeft (Pure.signMessage' h m g p b)

-- |Verify a signed message. You need to know what hash algorithm they used
-- to generate the signature, and pass it in. Returns True if the signature
-- was valid.
verifyMessage' :: HashFunction -> PublicKey -> ByteString -> Signature -> Bool
verifyMessage' = Pure.verifyMessage'

kViaExtraRandomBits :: CryptoRandomGen g => KGenerator g
kViaExtraRandomBits = Pure.kViaExtraRandomBits

kViaTestingCandidates :: CryptoRandomGen g => KGenerator g
kViaTestingCandidates = Pure.kViaTestingCandidates

kViaRFC6979 :: CryptoRandomGen g => KGenerator g
kViaRFC6979 = Pure.kViaRFC6979

-- | Using an approved hash function -- at the point of writing, a SHA-2
-- variant -- generate values of p and q for use in DSA, for which p and
-- q have a very high probability of being prime. In addition to p and q,
-- this routine returns the "domain parameter seed" and "counter" used to
-- generate the primes. These can be supplied to later validation functions;
-- their secrecy is not required for the algorithm to work.
--
-- The inputs to the function are the DSA parameters we are generating a
-- key for, a source of entropy, the hash function to use, and (optionally)
-- the length of the domain parameter seed to use. The last item must be
-- greater to or later to the value of n, if supplied, and will be set to
-- (n + 8) if not.
--
-- The security of this method depends on the strength of the hash being
-- used. To that end, FIPS 140-2 requires a SHA-2 variant.
generateProbablePrimes :: CryptoRandomGen g =>
                          ParameterSizes ->
                          g ->
                          (ByteString -> ByteString) ->
                          Maybe Integer ->
                          (Integer,Integer, ProbablePrimesEvidence, g)
generateProbablePrimes p g h i = 
  throwLeft (Pure.generateProbablePrimes p g h i)

-- |Validate that the probable primes that either you generated or that someone
-- provided to you are legitimate.
validateProbablePrimes :: CryptoRandomGen g =>
                          g {- A random number source -} ->
                          Integer {- ^p -} ->
                          Integer {- ^q -} ->
                          ProbablePrimesEvidence {- ^The evidence -} ->
                          (Bool, g)
validateProbablePrimes = Pure.validateProbablePrimes

-- |Using an approved hash function -- at the point of writing, a SHA-2
-- variant -- generate values of p and q for use in DSA, for which p and
-- q are provably prime. In addition to p and q, this routine generates
-- a series of additional values that can be used to validate that this
-- algorithm performed correctly.
--
-- The inputs to the function are the DSA parameters we are generating 
-- key for, a source of entropy, the hash function to use, and (optionally)
-- an initial seed length in bits. The last item, if provided, must be
-- greater than or equal to the N value being tested against, and must
-- be a multiple of 8.
generateProvablePrimes :: CryptoRandomGen g =>
                          ParameterSizes {- ^The DSA parameters to use -} ->
                          g {- ^source of randomness -} ->
                          (ByteString -> ByteString) {- ^Hash function -} ->
                          Maybe Integer {- ^Optional seed length, in bits. Must
                                            be greater than or equal to N, and
                                            divisible by 8. -} ->
                          (Integer, Integer, ProvablePrimesEvidence, g)
generateProvablePrimes a b c d = throwLeft (Pure.generateProvablePrimes a b c d)

-- |Validate that the provable primes that either you generated or that
-- someone provided to you are legitimate.
validateProvablePrimes :: Integer -> Integer ->
                          ProvablePrimesEvidence ->
                          Bool
validateProvablePrimes = Pure.validateProvablePrimes

-- |Generate the generator /g/ using a method that is not verifiable to a third
-- party. Quoth FIPS: "[This] method ... may be used when complete validation of
-- the generator /g/ is not required; it is recommended that this method be used
-- only when the party generating /g/ is trusted to not deliberately generate a
-- /g/ that has a potentially exploitable relationship to another generator
-- /g'/.
--
-- The input to this function are a valid /p/ and /q/, generated using an
-- approved method.
--
-- It may be possible (?) that this routine could fail to find a possible
-- generator. In that case, Nothing is returned.
generateUnverifiableGenerator :: Integer -> Integer -> Integer
generateUnverifiableGenerator p q =
  throwNothing (Pure.generateUnverifiableGenerator p q)

-- |Validate that the given generator /g/ works for the values /p/ and /q/
-- provided.
generatorIsValid :: Integer {- ^p -} -> Integer {- ^q -} ->
                    Integer {- ^g -} ->
                    Bool
generatorIsValid = Pure.generatorIsValid

-- |Generate a generator /g/, given the values of /p/, /q/, the evidence created
-- generating those values, and an index. Quoth FIPS: "This generation method
-- supports the generation of multiple values of /g/ for specific values of /p/
-- and /q/. The use of different values of /g/ for the same /p/ and /q/ may be
-- used to support key separation; for example, using the /g/ that is generated
-- with @index = 1@ for digital signatures and with @index = 2@ for key
-- establishment."
--
-- This method is replicatable, so that given the same inputs it will generate
-- the same outputs. Thus, you can validate that the /g/ generated using this
-- method was generated correctly using 'validateVerifiableGenerator', which
-- will be nice if you don't trust the person you're talking to.
generateVerifiableGenerator :: GenerationEvidence ev =>
                               Integer {- ^p -} -> Integer {- ^q -} ->
                               ev {- ^The evidence created generating /p/
                                     and /q/ -} ->
                               Word8 {- ^an index (This allows multiple /g/s
                                        from one pair) -} ->
                               Integer
generateVerifiableGenerator a b c d =
  throwNothing (Pure.generateVerifiableGenerator a b c d)

-- |Validate that the value /g/ was generated by 'generateVerifiableGenerator'
-- or someone using the same algorithm. This is probably a good idea if you
-- don't trust your compatriot. 
validateVerifiableGenerator :: GenerationEvidence ev =>
                               Integer {- ^p -} -> Integer {- ^q -} ->
                               ev {- ^The evidence created generating /p/
                                     and /q/ -} ->
                               Word8 {- ^an index (This allows multiple /g/s
                                        from one pair) -} ->
                               Integer {- ^g -} ->
                               Bool
validateVerifiableGenerator = Pure.validateVerifiableGenerator

--

throwNothing :: Maybe a -> a
throwNothing Nothing  = throw DSAInvalidInput
throwNothing (Just x) = x
