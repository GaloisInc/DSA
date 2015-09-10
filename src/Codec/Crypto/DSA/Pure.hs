{-# LANGUAGE BangPatterns       #-}
{-# LANGUAGE CPP                #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE MagicHash          #-}
{-# LANGUAGE MultiWayIf         #-}
module Codec.Crypto.DSA.Pure(
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
       , GenerationEvidence
       , generateUnverifiableGenerator
       , generatorIsValid
       , generateVerifiableGenerator
       , validateVerifiableGenerator
         -- * Exported only for testing.
         -- ** Prime number routines
       , millerRabin
       , isDeterministicallyPrime
       , shaweTaylor
         -- ** ByteString / Integer conversion
       , bs2int
       , bss2int
       , int2bs
         -- ** Miscellaneous numeric procedures
       , findAandM
       , modExp
       )
 where

import Control.Exception(Exception)
import Crypto.Random
import Crypto.Types.PubKey.DSA
import Data.Bits
import Data.ByteString.Lazy(ByteString)
import qualified Data.ByteString as BSS
import qualified Data.ByteString.Lazy as BS
import Data.Digest.Pure.SHA
import Data.Either
import Data.Int
import Data.Maybe
import Data.Tagged
import Data.Typeable
import Data.Word
import Prelude hiding (length)

#if defined(USE_GMP_HELPERS)
import GHC.Integer.GMP.Internals
import GHC.Types
#endif

data ParameterSizes = L1024_N160 | L2048_N224 | L2048_N256 | L3072_N256
 deriving (Eq, Show)

data DSAError = DSARandomGenerationError GenError
              | DSAInvalidSeedLength
              | DSAInvalidPrimeTestInput
              | DSAInvalidInput
              | DSAInternalInversionError
              | DSAGaveUp
 deriving (Eq, Show, Typeable)

instance Exception DSAError

-- |Get the N parameter, in bits.
getN :: ParameterSizes -> Integer
getN L1024_N160 = 160
getN L2048_N224 = 224
getN L2048_N256 = 256
getN L3072_N256 = 256

-- |Get the L parameter, in bits.
getL :: ParameterSizes -> Integer
getL L1024_N160 = 1024
getL L2048_N224 = 2048
getL L2048_N256 = 2048
getL L3072_N256 = 3072

-- |Generate a DSA key pair. This will also generate the /p/, /q/, and /g/
-- parameters using provable and verifiable algorithms, with SHA-256 as the
-- hash function. If you want to use your own /p/, /q/, and /g/ values or 
-- specify your own generation or hash function,, use the
-- 'generateKeyPairWithParams' function, below.
generateKeyPair :: CryptoRandomGen g =>
                   g -> ParameterSizes ->
                   Either DSAError (PublicKey, PrivateKey,
                                    ProvablePrimesEvidence, g)
generateKeyPair gen sizes =
  case generateProvablePrimes sizes gen sha256' Nothing of
    Left err               -> Left err
    Right (p, q, ev, gen') ->
      case generateVerifiableGenerator p q ev 0 of
        Nothing -> generateKeyPair gen' sizes
        Just g  ->
          case generateKeyPairWithParams (Params p g q) gen' of
            Left err                 -> Left err
            Right (pub, priv, gen'') -> Right (pub, priv, ev, gen'')
 where sha256' = bytestringDigest . sha256

-- |Generate a key pair given a set of DSA parameters. You really should have
-- validated this set (/p/, /q/, and /g/) using the relevant functions below
-- before you do this. Doing so even if you generated them is probably not a bad
-- practice.
--
-- This uses the method using extra random bits from FIPS 186-4. You better be
-- using a good enough random number generator.
generateKeyPairWithParams :: CryptoRandomGen g =>
                             Params -> g ->
                             Either DSAError (PublicKey, PrivateKey, g)
generateKeyPairWithParams params gen =
  case genBytes ((fromIntegral bigN + 64) `div` 8) gen of
    Left err -> Left (DSARandomGenerationError err)
    Right (returned_bits, gen') ->
      let c = bss2int returned_bits
          x = (c `mod` (q - 1)) + 1
          y = modExp g x p
      in Right (PublicKey params y, PrivateKey params x, gen')
 where
  bigN = intlen g
  p    = params_p params
  g    = params_g params
  q    = params_q params

-- |Sign a message using DSA. This method utilizes very good defaults for
-- message signing that should be acceptable for most use cases: it uses SHA-256
-- for the hash function, and generates /k/ using the methods described in RFC
-- 6979. If you wish to change these defaults, please see `signMessaage'`.
signMessage :: PrivateKey -> ByteString -> Either DSAError Signature
signMessage priv msg =
  case signMessage' SHA256 kViaRFC6979 NoGen priv msg of
    Left err       -> Left err
    Right (res, _) -> Right res

-- |Verify a DSA message signature. This uses the same default mechanisms as
-- `signMessage`.
verifyMessage :: PublicKey -> ByteString -> Signature -> Bool
verifyMessage = verifyMessage' SHA256

-- |The hash to use in generating the signature. We strongly recommend SHA256
-- or better.
data HashFunction = SHA1 | SHA224 | SHA256 | SHA384 | SHA512
 deriving (Eq, Show)

runHash :: HashFunction -> ByteString -> ByteString
runHash SHA1   = bytestringDigest . sha1
runHash SHA224 = bytestringDigest . sha224
runHash SHA256 = bytestringDigest . sha256
runHash SHA384 = bytestringDigest . sha384
runHash SHA512 = bytestringDigest . sha512

runHMac :: HashFunction -> ByteString -> ByteString -> ByteString
runHMac SHA1   k v = bytestringDigest (hmacSha1   k v)
runHMac SHA224 k v = bytestringDigest (hmacSha224 k v)
runHMac SHA256 k v = bytestringDigest (hmacSha256 k v)
runHMac SHA384 k v = bytestringDigest (hmacSha384 k v)
runHMac SHA512 k v = bytestringDigest (hmacSha512 k v)

getHashLength :: HashFunction -> Int64
getHashLength hash = BS.length (runHash hash BS.empty)

-- |Sign a message given the hash function an /k/ generation routine. Returns
-- either an error the signature generated. You can define your own /k/
-- generation routine ... but we don't recommend it. Actually, while we're
-- recommending, we recommend you use `kViaRFC6979`, if you're not sure
-- which to use.
signMessage' :: CryptoRandomGen g =>
                HashFunction -> KGenerator g -> g ->
                PrivateKey -> ByteString ->
                Either DSAError (Signature, g)
signMessage' hash genMeth gen privkey msg = loop kseq
 where
  params = private_params privkey
  p      = params_p params
  q      = params_q params
  g      = params_g params
  x      = private_x privkey
  bigN   = fromIntegral (intlen q)
  outlen = getHashLength hash
  kseq   = genMeth gen hash privkey msg
  --
  loop (KFailure err) = Left err
  loop (KValue k gen' next)
    | isNothing kinvres    = Left DSAInternalInversionError
    | (r == 0) || (s == 0) = loop next
    | otherwise            = Right (Signature r s, gen')
   where
    r = (modExp g k p) `mod` q
    z = bs2int (BS.take (min bigN outlen) (runHash hash msg))
    s = (kinv * (z + (x * r))) `mod` q
    kinvres = modInv k q
    Just kinv = kinvres

-- |Verify a signed message. You need to know what hash algorithm they used
-- to generate the signature, and pass it in. Returns True if the signature
-- was valid.
verifyMessage' :: HashFunction -> PublicKey -> ByteString -> Signature -> Bool
verifyMessage' hash pubkey msg sig
  | ((r' <= 0) || (r' >= q)) = False
  | ((s' <= 0) || (s' >= q)) = False
  | isNothing mw             = False
  | otherwise                = v == r'
 where
  r'     = sign_r sig
  s'     = sign_s sig
  p      = params_p (public_params pubkey)
  q      = params_q (public_params pubkey)
  g      = params_g (public_params pubkey)
  y      = public_y pubkey
  bigN   = fromIntegral (intlen q)
  outlen = BS.length (runHash hash BS.empty)
  --
  mw = modInv s' q
  w  = fromJust mw
  z  = bs2int (BS.take (min bigN outlen) (runHash hash msg))
  u1 = (z * w)  `mod` q
  u2 = (r' * w) `mod` q
  v  = (((modExp g u1 p) * (modExp y u2 p)) `mod` p) `mod` q

type KGenerator g = g -> HashFunction ->
                    PrivateKey -> ByteString ->
                    KSequence g

data CryptoRandomGen g => KSequence g = KValue   Integer  g (KSequence g)
                                      | KFailure DSAError

kViaExtraRandomBits :: CryptoRandomGen g => KGenerator g
kViaExtraRandomBits g hash privkey msg
  | isLeft randres = KFailure (DSARandomGenerationError err)
  | otherwise      = KValue k g' (kViaExtraRandomBits g' hash privkey msg)
 where
  q                         = params_q (private_params privkey)
  bigN                      = intlen q
  randres                   = genBytes (fromIntegral bigN + 64) g
  Left err                  = randres
  Right (returned_bits, g') = randres
  c                         = bss2int returned_bits
  k                         = (c `mod` (q - 1)) + 1

kViaTestingCandidates :: CryptoRandomGen g => KGenerator g
kViaTestingCandidates g hash privkey msg
  | isLeft randres = KFailure (DSARandomGenerationError err)
  | c > (q - 2)    = kViaTestingCandidates g' hash privkey msg
  | otherwise      = KValue k g' (kViaTestingCandidates g' hash privkey msg)
 where
  params                    = private_params privkey
  q                         = params_q params
  bigN                      = intlen q
  randres                   = genBytes (fromIntegral bigN) g
  Left err                  = randres
  Right (returned_bits, g') = randres
  c                         = bss2int returned_bits
  k                         = c + 1

kViaRFC6979 :: CryptoRandomGen g => KGenerator g
kViaRFC6979 g hash privkey msg = loop bigK_2 bigV_2
 where
  x     = private_x privkey
  q     = params_q (private_params privkey)
  qlen  = fromInteger (intlen q)
  h1    = runHash hash msg
  hlen  = BS.length h1
  --
  bigV_0 = BS.replicate hlen 1
  bigK_0 = BS.replicate hlen 0
  bigK_1 = runHMac hash bigK_0 (BS.concat [bigV_0, BS.singleton 0,
                                           int2octets x, bits2octets h1])
  bigV_1 = runHMac hash bigK_1 bigV_0
  bigK_2 = runHMac hash bigK_1 (BS.concat [bigV_1, BS.singleton 1,
                                           int2octets x, bits2octets h1])
  bigV_2 = runHMac hash bigK_2 bigV_1
  --
  buildT bigK bigV bigT | BS.length bigT >= qlen = (bigV, bits2int bigT)
                        | otherwise              = buildT bigK bigV' bigT'
   where
    bigV' = runHMac hash bigK bigV
    bigT' = bigT `BS.append` bigV'
  --
  loop bigK bigV | (1 <= k) && (k <= (q - 1)) = KValue k g (loop bigK' bigV'')
                 | otherwise                  = loop bigK' bigV''
   where
    (bigV', k) = buildT bigK bigV BS.empty
    bigK'      = runHMac hash bigK  (bigV' `BS.append` BS.singleton 0)
    bigV''     = runHMac hash bigK' bigV'
  --
  bitlen :: Integer -> Int
  bitlen y = go y 0
   where
    go 0 acc = acc
    go v acc = go (v `shiftR` 1) (acc + 1)
  --
  bits2int :: ByteString -> Integer
  bits2int bstr | qbtlen < blen = value `shiftR` (blen - qbtlen)
                | otherwise     = value
   where
    blen   = fromIntegral (BS.length bstr * 8)
    qbtlen = bitlen q
    value  = bs2int bstr
  --
  bits2octets :: ByteString -> ByteString
  bits2octets bstr = BS.replicate (qlen - BS.length res) 0 `BS.append` res
   where
    res  = int2bs (z1 `mod` q)
    z1   = bits2int bstr
  --
  int2octets :: Integer -> ByteString
  int2octets y
    | BS.length out < qlen = padding `BS.append` out
    | BS.length out > qlen = BS.drop (BS.length out - qlen) out
    | otherwise            = out
   where
    out     = int2bs y
    padding = BS.replicate (qlen - BS.length out) 0

-- |The evidence generated when generating probably primes. This evidence can
-- be used to ensure that the /p/ and /q/ values provided were generated
-- appropriately.
data ProbablePrimesEvidence = ProbablePrimesEvidence {
       prpeDomainParameterSeed :: ByteString
     , prpeCounter             :: Integer
     , prpeHash                :: ByteString -> ByteString
     }

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
                          Either DSAError (Integer,Integer,
                                           ProbablePrimesEvidence,
                                           g)
generateProbablePrimes dsaParam gen hash Nothing =
  generateProbablePrimes dsaParam gen hash (Just (getN dsaParam + 8))
generateProbablePrimes dsaParam gen hash (Just seedlen)
  | seedlen < getN dsaParam = Left DSAInvalidSeedLength
  | seedlen `mod` 8 /= 0    = Left DSAInvalidSeedLength
  | otherwise               = find_q gen
 where
  outlenB           = fromIntegral (BS.length (hash BS.empty)) -- in bytes
  outlen            = outlenB * 8                              -- in bits
  outlenF           = fromInteger outlen :: Double
  bigL              = fromIntegral (getL dsaParam) :: Integer  -- in bits
  bigN              = fromIntegral (getN dsaParam) :: Integer  -- in bits
  n                 = ceiling (fromInteger bigL / outlenF) - 1
  b                 = bigL - 1 - (n * outlen)
  --
  find_q g'
    | isLeft dpsEth   = Left (DSARandomGenerationError err)
    | isLeft primeEth = Left primeErr
    | isPrime         = find_p g''' 1 0 q domParamSeed
    | otherwise       = find_q g'''
   where
    dpsEth                = genBytes (fromIntegral ((seedlen + 7) `div` 8)) g'
    Left err              = dpsEth
    Right (dpsBS, g'')    = dpsEth
    domParamSeed          = BS.fromStrict dpsBS
    mask                  = 2 ^ (bigN - 1)
    bigU                  = bs2int (hash domParamSeed) `mod` mask
    q                     = mask + bigU + 1 - (bigU `mod` 2)
    primeEth              = isPrimeC3 g'' dsaParam q
    Left primeErr         = primeEth
    Right (isPrime, g''') = primeEth
  --
  find_p g' !off !ctr !q !dpsBS
    | ctr == fourTimesL = find_q g'
    | p < twoLm1        = find_p g' off' ctr' q dpsBS
    | isLeft primeEth   = Left primeErr
    | isPrime           = let ev = ProbablePrimesEvidence dpsBS ctr hash
                          in Right (p, q, ev, g'')
    | otherwise         = find_p g'' off' ctr' q dpsBS
   where
    dps                  = bs2int (dpsBS :: ByteString) :: Integer
    !bigW                = computeW hash dps off n b seedlen
    bigX                 = bigW + (2 ^ (bigL - 1))
    c                    = bigX `mod` (2 * q)
    p                    = bigX - (c - 1)
    primeEth             = isPrimeC3 g' dsaParam p
    Left primeErr        = primeEth
    Right (isPrime, g'') = primeEth
    off'                 = off + n + 1
    ctr'                 = ctr + 1
  --
  fourTimesL = 4 * bigL
  twoLm1     = 2 ^ (bigL - 1)

computeW :: (ByteString -> ByteString) ->
            Integer -> Integer -> Integer -> Integer -> Integer ->
            Integer
computeW hash dps offset n b seedlen = loop 0 BS.empty
 where
  loop j acc | j == n    = bs2int (vj' `BS.append` acc)
             | otherwise = loop (j + 1) (vj `BS.append` acc)
   where
    vj  = hash (int2bs ((dps + offset + j) `mod` (2 ^ seedlen)))
    vj' = int2bs (bs2int vj `mod` (2 ^ b))

-- |Validate that the probable primes that either you generated or that someone
-- provided to you are legitimate.
validateProbablePrimes :: CryptoRandomGen g =>
                          g {- A random number source -} ->
                          Integer {- ^p -} ->
                          Integer {- ^q -} ->
                          ProbablePrimesEvidence {- ^The evidence -} ->
                          (Bool, g)
validateProbablePrimes g p q (ProbablePrimesEvidence dps counter hash) =
  if | not goodParam              -> (False, g)
     | counter > ((4 * bigL) - 1) -> (False, g)
     | seedlen < bigN             -> (False, g)
     | computed_q /= q            -> (False, g)
     | not computed_q_prime       -> (False, g')
     | otherwise                  -> counter_right
 where
  -- 1. L = len (p).
  bigL = intlen p * 8
  -- 2. N = len (q).
  bigN = intlen q * 8
  -- 3. Check that the (L, N) pair is in the list of acceptable (L, N) pairs
  --    (see Section 4.2). If the pair is not in the list, return INVALID.
  --    [See the first line above]
  (param, goodParam) =
    case (bigL, bigN) of
      (1024, 160) -> (L1024_N160, True)
      (2048, 224) -> (L2048_N224, True)
      (2048, 256) -> (L2048_N256, True)
      (3072, 256) -> (L3072_N256, True)
      _           -> ((error ("PARAM: "++show bigL++" "++show bigN)), False)
  -- 4. If (counter > (4L – 1)), then return INVALID.
  --    [See the second line above]
  -- 5. seedlen = len (domain_parameter_seed).
  seedlen = fromIntegral (BS.length dps * 8)
  -- 6. If (seedlen < N), then return INVALID.
  --    [See the third line above]
  -- 7. U = Hash(domain_parameter_seed) mod 2N–1
  bigU = bs2int (hash dps) `mod` (2 ^ (bigN - 1))
  -- 8. computed_q = 2^(N–1) + U + 1 – ( U mod 2).
  computed_q = (2 ^ (bigN - 1)) + bigU + 1 - (bigU `mod` 2)
  -- 9. Test whether or not computed_q is prime as specified in Appendix C.3.
  --    If (computed_q ≠ q) or (computed_q is not prime), then return INVALID.
  --    [See the fourth line above]
  (computed_q_prime, g') = case isPrimeC3 g param computed_q of
                             Left _  -> (False, g)
                             Right x -> x
  outlenB           = fromIntegral (BS.length (hash BS.empty)) -- in bytes
  outlen            = outlenB * 8                              -- in bits
  outlenF           = fromInteger outlen :: Double
  n                 = ceiling (fromInteger bigL / outlenF) - 1
  b                 = bigL - 1 - (n * outlen)
  -- 12. offset = 1.
  offset = 1
  -- 13. For i = 0 to counter do
  counter_right = loop g' 0 offset
  loop gen !i !off
    | isLeft primeEth               = (False, gen)
    | i == counter                  = step14 gen i computed_p isPrime
    | computed_p < (2 ^ (bigL - 1)) = loop gen (i + 1) off'
    | isPrime                       = step14 gen i computed_p isPrime
    | otherwise                     = loop gen' (i + 1) off'
   where
    bigW                  = computeW hash (bs2int dps) off n b seedlen
    bigX                  = bigW + (2 ^ (bigL - 1))
    c                     = bigX `mod` (2 * q)
    computed_p            = bigX - (c - 1)
    primeEth              = isPrimeC3 gen param computed_p
    Right (isPrime, gen') = primeEth
    off'                  = off + n + 1
  --
  step14 gen i computed_p isPrime = (res, gen)
    where res = (i == counter) && (computed_p == p) && isPrime


data ProvablePrimesEvidence = ProvablePrimesEvidence {
       pvpeFirstSeed   :: Integer
     , pvpePSeed       :: Integer
     , pvpeQSeed       :: Integer
     , pvpePGenCounter :: Integer
     , pvpeQGenCounter :: Integer
     , pvpeHash        :: ByteString -> ByteString
     }

instance Eq ProvablePrimesEvidence where
  ev1 == ev2 = (pvpeFirstSeed   ev1 == pvpeFirstSeed   ev2) &&
               (pvpePSeed       ev1 == pvpePSeed       ev2) &&
               (pvpeQSeed       ev1 == pvpeQSeed       ev2) &&
               (pvpePGenCounter ev1 == pvpePGenCounter ev2) &&
               (pvpeQGenCounter ev1 == pvpeQGenCounter ev2)

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
                          Either DSAError (Integer, Integer,
                                           ProvablePrimesEvidence, g)
generateProvablePrimes params g hash Nothing =
  generateProvablePrimes params g hash (Just (getN params))
generateProvablePrimes params g hash (Just seedlen)
  | seedlen < bigN       = Left DSAInvalidSeedLength
  | seedlen `mod` 8 /= 0 = Left DSAInvalidSeedLength
  | isLeft mfirstseed    = reLeft mfirstseed
  | otherwise            = 
      case constructivePrimeGen hash bigL bigN firstseed of
        Left DSAGaveUp -> generateProvablePrimes params g' hash (Just seedlen)
        Left err       -> Left err
        Right (p,q,ev) -> Right (p,q,ev,g')
 where
  bigN    = getN params :: Integer
  bigL    = getL params :: Integer
  twonm1  = 2 ^ (bigN - 1)
  --
  mfirstseed = getFirstSeed g 0
  Right (firstseed, g') = getFirstSeed g 0
  --
  getFirstSeed gen first_seed
   | first_seed >= twonm1 = Right (first_seed, gen)
   | otherwise            =
      case genBytes (fromIntegral (bigN `div` 8)) gen of
        Left err            -> Left (DSARandomGenerationError err)
        Right (bytes, gen') -> getFirstSeed gen' (bss2int bytes)

constructivePrimeGen :: (ByteString -> ByteString) ->
                        Integer -> Integer -> Integer ->
                        Either DSAError (Integer,Integer,ProvablePrimesEvidence)
constructivePrimeGen hash bigL bigN firstseed
  | isLeft mqseed        = reLeft mqseed
  | isLeft mpseed        = reLeft mpseed
  | otherwise            = runCheck pgen_counter pseed' t0
 where
  outlenF = fromIntegral (BS.length (hash BS.empty)) * (8.0 :: Double)
  mqseed = shaweTaylor hash bigN                 firstseed
  mpseed = shaweTaylor hash ((bigL `div` 2) + 1) qseed
  Right (q, qseed, qgen_counter)  = mqseed
  Right (p0, pseed, pgen_counter) = mpseed
  iterations = ceiling (fromInteger bigL / outlenF) - 1
  old_counter = pgen_counter
  x = bs2int (BS.concat (map (\ i -> hash (int2bs (pseed + i)))
                             (reverse [0..iterations])))
  pseed' = pseed + iterations + 1
  x' = (2 ^ (bigL - 1)) + (x `mod` (2 ^ (bigL - 1)))
  t0 = ceiling (fromInteger x' /
                ((2.0 :: Double) * fromInteger q * fromInteger p0))
  runCheck pgc ps t
    | (1 == gcd (z - 1) p) && (1 == modExp z p0 p) =
        let ev = ProvablePrimesEvidence firstseed ps' qseed
                                        pgc' qgen_counter hash
        in Right (p, q, ev)
    | pgc' > ((4 * bigL) + old_counter) =
        Left DSAGaveUp
    | otherwise =
        runCheck pgc' ps' (t + 1)
   where
    t' | (2 * t * q * p0) + 1 > (2 ^ bigL) =
           ceiling (((2.0 :: Double) ^ (bigL - 1)) /
                    ((2.0 :: Double) * fromInteger q * fromInteger p0))
       | otherwise = t
    p = (2 * t' * q * p0) + 1
    pgc' = pgc + 1
    a = bs2int (BS.concat (map (\ i -> hash (int2bs (pseed + i)))
                               (reverse [0..iterations])))
    ps' = ps + iterations + 1
    a' = 2 + (a `mod` (p - 3))
    z  = modExp a' (2 * t' * q) p

reLeft :: Either a b -> Either a c
reLeft (Left a)  = Left a
reLeft (Right _) = error "Re-left of a Right value"

-- |Validate that the provable primes that either you generated or that
-- someone provided to you are legitimate.
validateProvablePrimes :: Integer -> Integer ->
                          ProvablePrimesEvidence ->
                          Bool
validateProvablePrimes p q ev =
   ((bigL, bigN) `elem` [(1024,160),(2048,224),(2048,256),(3072,256)]) && -- 3
   (pvpeFirstSeed ev >= (2 ^ (bigN - 1)))                              && -- 4
   ((2 ^ bigN) > q)                                                    && -- 5
   ((2 ^ bigL) > p)                                                    && -- 6
   ((p - 1) `mod` q == 0)                                              && -- 7
   isRight mres && (p == p') && (q == q') && (ev == ev')                  -- 8
 where
  bigL = intlen p * 8
  bigN = intlen q * 8
  hash = pvpeHash ev
  mres = constructivePrimeGen hash bigL bigN (pvpeFirstSeed ev)
  Right (p', q', ev') = mres

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
generateUnverifiableGenerator :: Integer -> Integer -> Maybe Integer
generateUnverifiableGenerator p q = loop 2
 where
  e = (p - 1) `div` q
  loop h | h >= (p - 1) = Nothing
         | g == 1       = loop (h + 1)
         | otherwise    = Just g
   where g = modExp h e p

-- |Validate that the given generator /g/ works for the values /p/ and /q/
-- provided.
generatorIsValid :: Integer {- ^p -} -> Integer {- ^q -} ->
                    Integer {- ^g -} ->
                    Bool
generatorIsValid p q g = rangeOK && modOK
 where
  rangeOK = (2 <= g) && (g <= (p - 1))
  modOK   = modExp g q p == 1

class GenerationEvidence a where
  getHash                :: a -> (ByteString -> ByteString)
  getDomainParameterSeed :: a -> ByteString

instance GenerationEvidence ProbablePrimesEvidence where
  getHash                = prpeHash
  getDomainParameterSeed = prpeDomainParameterSeed

instance GenerationEvidence ProvablePrimesEvidence where
  getHash                  = pvpeHash
  getDomainParameterSeed e = BS.concat [firstSeed, pseed, qseed]
   where
    firstSeed = int2bs (pvpeFirstSeed e)
    pseed     = int2bs (pvpePSeed e)
    qseed     = int2bs (pvpeQSeed e)

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
                               ev {- ^The evidence created generating /p/ and /q/ -} ->
                               Word8 {- ^an index (This allows multiple /g/s from one pair) -} ->
                               Maybe Integer
generateVerifiableGenerator p q ev index = loop (1 :: Word16)
 where
--  bigN    = intlen q    AW: Not sure why the spec asks us to compute this ...
  e       = (p - 1) `div` q
  indexBS = BS.singleton index
  ggen    = int2bs 0x6767656e
  --
  loop count | count == 0 = Nothing
             | g < 2      = loop (count + 1)
             | otherwise  = Just g
   where
    countBS = BS.pack [fromIntegral (count `shiftR` 8), fromIntegral (count .&. 0xFF)]
    bigU    = getDomainParameterSeed ev `BS.append` ggen `BS.append` indexBS `BS.append` countBS
    bigW    = bs2int (getHash ev bigU)
    g       = modExp bigW e p

-- |Validate that the value /g/ was generated by 'generateVerifiableGenerator'
-- or someone using the same algorithm. This is probably a good idea if you
-- don't trust your compatriot. 
validateVerifiableGenerator :: GenerationEvidence ev =>
                               Integer {- ^p -} -> Integer {- ^q -} ->
                               ev {- ^The evidence created generating /p/ and /q/ -} ->
                               Word8 {- ^an index (This allows multiple /g/s from one pair) -} ->
                               Integer {- ^g -} ->
                               Bool
validateVerifiableGenerator p q ev index g = rangeOK && modOK && genOK
 where
  rangeOK = (2 <= g) && (g <= (p - 1))
  modOK   = modExp g q p == 1
  genOK   = case generateVerifiableGenerator p q ev index of
              Nothing         -> False
              Just computed_g -> computed_g == g

-- |Determine if a given value is probably prime, using a testing procedure
-- appropriate for the given DSA parameters. (The probability of an error is
-- somewhere between 2^-80 and 2^-128, depending on the strength of the DSA
-- parameters.)
--
-- This is based on the definitions in FIPS 186-4, Appendic C.3.
isPrimeC3 :: CryptoRandomGen g =>
             g -> ParameterSizes -> Integer ->
             Either DSAError (Bool, g)
isPrimeC3 g L1024_N160 !x = millerRabin g 40 x
isPrimeC3 g L2048_N224 !x = millerRabin g 56 x
isPrimeC3 g L2048_N256 !x = millerRabin g 56 x
isPrimeC3 g L3072_N256 !x = millerRabin g 64 x

-- |Perform the given number of iterations of the Miller-Rabin test to try
-- to determine if the given Integer is prime.
millerRabin :: CryptoRandomGen g =>
               g -> Int -> Integer ->
               Either DSAError (Bool, g)
#if defined(USE_GMP_HELPERS)
millerRabin gen (I# its) w
 | w == 1    = Right (False, gen)
 | w == 2    = Right (True,  gen)
 | even w    = Left DSAInvalidPrimeTestInput
 | otherwise =
     case testPrimeInteger w its of
       0# -> Right (False, gen)
       _  -> Right (True, gen)
#else
millerRabin gen iterations w
 | w == 0    = Left DSAInvalidPrimeTestInput
 | w == 1    = Right (False, gen)
 | w == 2    = Right (True,  gen)
 | w == 3    = Right (True,  gen)
 | even w    = Left DSAInvalidPrimeTestInput
 | otherwise = result
  -- INPUT:
  --   1. w: The odd integer to be tested for primality.
  --   2. iterations: The number of iterations of the test to be performed;
  --      the value SHALL be consistent with Table C.1, C.2, or C.3
  --      [in this case, Table C.1 is the isPrimeC3 -> millerRabin function,
  --       above]
 where
  -- PROCESS:
  --   1. Let a bet the largest integer such that 2^a divides (w - 1)
  --   2. m = (w - 1) / 2^a
  (a, m) = findAandM (w - 1)
  --   3. wlen = len (w)
  wlen = intlen w
  --   4. For i = 1 to iterations do
  result = go gen iterations
  --   5. Return PROBABLY PRIME / true
  go g 0 = Right (True, g)
  go g count
    | isLeft genEth              = Left (DSARandomGenerationError err)
    | ((b <= 1) || (b >= w - 1)) = go g' count
    | ((z == 1) || (z == w - 1)) = go g' (count - 1)
    | otherwise                  = step45loop g' count z 1
   where
    genEth           = genBytes (fromIntegral wlen) g
    Left err         = genEth
    Right (bstr, g') = genEth
    --
    b = bss2int bstr
    z = modExp b m w
  --
  step45loop g count !z !j | j == a        = Right (False, g)
                           | z' == (w - 1) = go g (count - 1)
                           | z' == 1       = Right (False, g)
                           | otherwise     = step45loop g count z' (j + 1)
   where z' = modExp z 2 w
#endif

bss2int :: BSS.ByteString -> Integer
bss2int bstr = go 0 (BSS.unpack bstr)
 where
  go acc []    = acc
  go acc (h:t) = go ((acc `shiftL` 8) + fromIntegral h) t

modExp :: Integer -> Integer -> Integer -> Integer
#if defined(USE_GMP_HELPERS)
modExp !x !y !m = powModInteger x y m
#else
modExp !x !y !m = go x y 1
 where
  go _   0 !result = result
  go !b !e !result = go ((b * b) `mod` m) (e `shiftR` 1) result'
   where result' = if testBit e 0 then (result * b) `mod` m else result
#endif

modInv :: Integer -> Integer -> Maybe Integer
modInv !z !a = loop a z 0 1
 where
  loop i j y2 y1 | j' > 0     = loop i' j' y2' y1'
                 | i' /= 1    = Nothing
                 | otherwise  = Just (y2' `mod` a)
   where
    quotient  = i `div` j
    remainder = i - (j * quotient)
    y         = y2 - (y1 * quotient)
    i'        = j
    j'        = remainder
    y2'       = y1
    y1'       = y

xorbs :: ByteString -> ByteString -> ByteString
xorbs a b = BS.pack (BS.zipWith xor a b)

-- |Find 'a' and 'm' such that input = 2^a * m.
findAandM :: Integer -> (Integer, Integer)
findAandM x = go 0 x
 where
  go acc v | even v    = go (acc + 1) (v `div` 2)
           | otherwise = (acc, v)

intlen :: Integer -> Integer
intlen 0 = 0
intlen x = intlen (x `shiftR` 8) + 1

-- |Convert a ByteString into its obvious Integer representation.
bs2int :: ByteString -> Integer
bs2int bstr = go 0 (BS.unpack bstr)
 where
  go acc []    = acc
  go acc (h:t) = go ((acc `shiftL` 8) + fromIntegral h) t

-- |Convert an Integer into its obvious ByteString representation.
int2bs :: Integer -> ByteString
int2bs x
  | x < 0     = error "int2bs: negative input"
  | x == 0    = BS.empty
  | otherwise = int2bs (x `shiftR` 8) `BS.append`
                BS.singleton (fromIntegral (x .&. 0xFF))

shaweTaylor :: (ByteString -> ByteString) -> Integer -> Integer ->
               Either DSAError (Integer, Integer, Integer)
shaweTaylor hash length input_seed
  | length < 2   = Left DSAInvalidInput
  | length >= 33 = largeVersion
  | otherwise    = smallVersion input_seed 0
 where
  -- Steps 1 - 13 in Appendix C.6
  smallVersion prime_seed prime_gen_counter
     | isDeterministicallyPrime c7 = Right (c7, prime_seed, prime_gen_counter)
     | prime_gen_counter > (4 * length) = Left DSAGaveUp
     | otherwise = smallVersion ps' pgc'
    where
     c5 = bs2int ((hash (int2bs prime_seed)) `xorbs`
                  (hash (int2bs (prime_seed + 1))))
     c6 = (2 ^ (length - 1)) + (c5 `mod` (2 ^ (length - 1)))
     c7 = (2 * floor (fromInteger c6 / (2.0 :: Double))) + 1
     pgc' = prime_gen_counter + 1
     ps'  = prime_seed + 2
  -- Steps 14 - 34 in Appendix C.6
  largeVersion
    | isLeft mstatus = reLeft mstatus
    | otherwise      = findLoop prime_gen_counter prime_seed' t0
   where
    outlenF = fromIntegral (BS.length (hash BS.empty)) * (8.0 :: Double)
    ceildiv = ceiling (fromInteger length / (2 :: Double)) + 1
    mstatus = shaweTaylor hash ceildiv input_seed
    Right (c0, prime_seed, prime_gen_counter) = mstatus
    iterations = ceiling (fromInteger length / outlenF) - 1
    old_counter = prime_gen_counter
    x = bs2int (BS.concat (map (\ i -> hash (int2bs (prime_seed + i)))
                               (reverse [0..iterations])))
    prime_seed' = prime_seed + iterations + 1
    x' = (2 ^ (length - 1)) + (x `mod` (2 ^ (length - 1)))
    t0 = ceiling (fromInteger x' / ((2.0 :: Double) * fromInteger c0))
    -- steps 23 - 34
    findLoop pgc ps !t
      | (1 == gcd (z - 1) c) && (1 == modExp z c0 c) =
          Right (c, ps', pgc')
      | pgc' >= ((4 * length) + old_counter) =
          Left DSAGaveUp
      | otherwise =
          findLoop pgc' ps' (t' + 1)
     where
      t' | ((2 * t * c0) + 1) > (2 ^ length) = 
             ceiling (((2 :: Double) ^ (length - 1)) /
                      ((2.0 :: Double) * fromInteger c0))
         | otherwise = t
      c = 2 * t * c0 + 1
      pgc' = pgc + 1
      a = bs2int (BS.concat (map (\ i -> hash (int2bs (ps + i)))
                                 (reverse [0..iterations])))
      ps' = ps + iterations + 1
      a' = 2 + (a `mod` (c - 3))
      z = modExp a' (2 * t) c

-- |A brute force check to determine if a number is prime. This answer is
-- guaranteed to be correct, but should only be used on small numbers (less
-- than 33 bits would be nice).
isDeterministicallyPrime :: Integer -> Bool
isDeterministicallyPrime !x
  | x <= 1    = False
  | x == 2    = True
  | even x    = False
  | otherwise = go 2
 where
  final = ceiling (sqrt (fromInteger x :: Double))
  go !d | d >  final     = True
        | x `mod` d == 0 = False
        | otherwise      = go (nextDivisor d)
  --
  nextDivisor 2 = 3
  nextDivisor 3 = 5
  nextDivisor 5 = 7
  nextDivisor d | d' `mod` 3 == 0 = nextDivisor (d + 2)
                | d' `mod` 5 == 0 = nextDivisor (d + 2)
                | otherwise       = d'
   where d' = d + 2

data NoGen = NoGen
instance CryptoRandomGen NoGen where
  newGen        _   = Left NotEnoughEntropy
  genSeedLength     = Tagged 0
  genBytes      _ _ = Left NotEnoughEntropy
  reseedInfo    _   = Never
  reseedPeriod  _   = Never
  reseed        _ _ = Left NotEnoughEntropy

