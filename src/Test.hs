{-# LANGUAGE CPP                 #-}
{-# LANGUAGE ScopedTypeVariables #-}
import Codec.Crypto.DSA.Pure
import Crypto.Random.DRBG
import Data.Bits
import Data.ByteString.Lazy(ByteString, toStrict, pack)
import qualified Data.ByteString.Lazy.Char8 as BSC
import Data.Digest.Pure.SHA
import Data.Word
import Test.Framework(defaultMain, testGroup, Test)
import Test.Framework.Providers.QuickCheck2(testProperty)
import Test.Framework.Providers.HUnit(testCase)
import Test.HUnit.Base(Assertion,assertEqual)
import Test.QuickCheck hiding ((.&.))
import Debug.Trace

data ArbHashFunction = HF String (ByteString -> ByteString)

instance Eq ArbHashFunction where
  (HF a _) == (HF b _) = a == b

instance Show ArbHashFunction where
  show (HF a _) = "<" ++ a ++ ">"

instance Arbitrary ParameterSizes where
#ifdef BETTER_TESTS
  arbitrary = elements [L1024_N160, L2048_N224, L2048_N256, L3072_N256]
#else
  arbitrary = return L1024_N160
#endif

instance Arbitrary ArbHashFunction where
  arbitrary = elements [ HF "SHA224" (bytestringDigest . sha224)
                       , HF "SHA256" (bytestringDigest . sha256)
                       , HF "SHA384" (bytestringDigest . sha384)
                       , HF "SHA512" (bytestringDigest . sha512)
                       ]

main :: IO ()
main =
  do g :: GenAutoReseed HashDRBG HashDRBG <- newGenIO
     defaultMain [
       testGroup "Basic helper functions" [
            testProperty "ByteString / Integer conversion round-trips"
                         prop_int2bs_roundtrips
          , testProperty "ByteString / Integer conversion round-trips (v2)"
                         prop_int2bs_roundtrips2
          , testProperty "Can find appropriate factors"
                         prop_findAandM_works
          , testProperty "Fast modular exponentiation works."
                         prop_modExp_works
          , testProperty "Deterministic prime checking works."
                         prop_isDetPrimeWorks
          , testProperty "Miller-Rabin primality test seems to work"
                         (prop_mr_computes_primes g)
          , testProperty "Shawe-Taylor algorithm generates primes"
                         (prop_shaweTaylorWorks g)
         ]
         , testGroup "DSA Generation functions" [
            testProperty "Probable primes validate"
                         (prop_validateProbPrimes g)
          , testProperty "Provable primes validate"
                         (prop_validateProvPrimes g)
          , testProperty "Unverifiable g generation works" (prop_validateUnvG g)
          , testProperty "Verifiable g generation works" (prop_validateVerG g)
         ]
       , testGroup "RFC 6969 test cases" [
           testCase "Base RFC6979 k-generation test case" (test_RFCKGen g)
         , testGroup "RFC6979 A.2.1 (SHA1 sample)"   (test_RFCA21_1sample g)
         , testGroup "RFC6979 A.2.1 (SHA224 sample)" (test_RFCA21_224sample g)
         , testGroup "RFC6979 A.2.1 (SHA256 sample)" (test_RFCA21_256sample g)
         , testGroup "RFC6979 A.2.1 (SHA384 sample)" (test_RFCA21_384sample g)
         , testGroup "RFC6979 A.2.1 (SHA512 sample)" (test_RFCA21_512sample g)
         , testGroup "RFC6979 A.2.1 (SHA1 test)"     (test_RFCA21_1test g)
         , testGroup "RFC6979 A.2.1 (SHA224 test)"   (test_RFCA21_224test g)
         , testGroup "RFC6979 A.2.1 (SHA256 test)"   (test_RFCA21_256test g)
         , testGroup "RFC6979 A.2.1 (SHA384 test)"   (test_RFCA21_384test g)
         , testGroup "RFC6979 A.2.1 (SHA512 test)"   (test_RFCA21_512test g)
         , testGroup "RFC6979 A.2.2 (SHA1 sample)"   (test_RFCA22_1sample g)
         , testGroup "RFC6979 A.2.2 (SHA224 sample)" (test_RFCA22_224sample g)
         , testGroup "RFC6979 A.2.2 (SHA256 sample)" (test_RFCA22_256sample g)
         , testGroup "RFC6979 A.2.2 (SHA384 sample)" (test_RFCA22_384sample g)
         , testGroup "RFC6979 A.2.2 (SHA512 sample)" (test_RFCA22_512sample g)
         , testGroup "RFC6979 A.2.2 (SHA1 test)"     (test_RFCA22_1test g)
         , testGroup "RFC6979 A.2.2 (SHA224 test)"   (test_RFCA22_224test g)
         , testGroup "RFC6979 A.2.2 (SHA256 test)"   (test_RFCA22_256test g)
         , testGroup "RFC6979 A.2.2 (SHA384 test)"   (test_RFCA22_384test g)
         , testGroup "RFC6979 A.2.2 (SHA512 test)"   (test_RFCA22_512test g)
         ]
       , testGroup "End-to-end tests" [
           testProperty "Verify verifies signed messages" (prop_verifySig g)
         , testProperty "Verify verifies signed messages (v2)" (prop_verifySig' g)
         ]
       ]

prop_int2bs_roundtrips :: Positive Integer -> Bool
prop_int2bs_roundtrips px = x == bs2int (int2bs x)
 where x = getPositive px

prop_int2bs_roundtrips2 :: Positive Integer -> Bool
prop_int2bs_roundtrips2 px = x == bss2int (toStrict (int2bs x))
 where x = getPositive px

prop_findAandM_works :: Positive Integer -> Bool
prop_findAandM_works px
  | x <= 3    = True
  | otherwise = x == ((2 ^ a) * m)
 where
  x = getPositive px
  (a, m) = findAandM x

prop_modExp_works :: Positive Integer ->
                     Positive Integer ->
                     Positive Integer ->
                     Bool
prop_modExp_works px py pm = modExp x y m == ((x ^ y) `mod` m)
 where
  x = getPositive px
  y = getPositive py
  m = getPositive pm

prop_isDetPrimeWorks :: Positive Integer -> Bool
prop_isDetPrimeWorks px = isPrime x == isDeterministicallyPrime x
 where x = getPositive px

newtype OddPositive = OP Integer

instance Arbitrary OddPositive where
  arbitrary = do x <- arbitrary
                 return (OP (abs x .|. 1))

instance Show OddPositive where
  show (OP x) = show x

prop_mr_computes_primes :: CryptoRandomGen g =>
                           g -> OddPositive -> Bool
prop_mr_computes_primes g (OP x) =
  case millerRabin g 64 x of
    Left _       -> False
    Right (v, _) -> v == isDeterministicallyPrime x

newtype RandBitLength = BL Integer

instance Arbitrary RandBitLength where
#ifdef BETTER_TESTS
  arbitrary = BL `fmap` choose (2,1538)
#else
  arbitrary = BL `fmap` choose (2,128)
#endif

instance Show RandBitLength where
  show (BL x) = show x

prop_shaweTaylorWorks :: CryptoRandomGen g =>
                         g -> ArbHashFunction -> RandBitLength ->
                         Positive Integer ->
                         Bool
prop_shaweTaylorWorks g (HF _ h) (BL l) seed =
  case shaweTaylor h l (getPositive seed) of
    Left _ -> True
    Right (x, _, _) ->
      case millerRabin g 64 x of
        Left _ -> False
        Right (res, _) -> res

isPrime :: Integer -> Bool
isPrime x | x <= 1    = False
          | x == 2    = True
          | even x    = False
          | otherwise = go 3
 where
  go y | y >= x         = True
       | x `mod` y == 0 = False
       | otherwise      = go (y + 2)

prop_validateProbPrimes :: CryptoRandomGen g =>
                           g -> ParameterSizes -> ArbHashFunction ->
                           Maybe (Positive Integer) ->
                           Bool
prop_validateProbPrimes g params (HF _ hash) mseedlen =
  case generateProbablePrimes params g hash mseedlen' of
    Left err -> trace (show err) False
    Right (p, q, ev, g') ->
        let (res, _) = validateProbablePrimes g' p q ev
        in if not res
              then trace ("FAIL p = " ++ show p ++ " q = " ++ show q) False
              else True
 where mseedlen' = fmap (\ x -> (getPositive x * 8) + getN params) mseedlen

prop_validateProvPrimes :: CryptoRandomGen g =>
                           g -> ParameterSizes -> ArbHashFunction ->
                           Maybe (Positive Integer) ->
                           Bool
prop_validateProvPrimes g params (HF _ hash) mseedlen =
  case generateProvablePrimes params g hash mseedlen' of
    Left err -> trace (show err) False
    Right (p, q, ev, _) ->
        let res = validateProvablePrimes p q ev
        in if not res
              then trace ("FAIL p = " ++ show p ++ " q = " ++ show q ++ " mseedlen': " ++ show mseedlen' ++ " firstSeed: " ++ show (pvpeFirstSeed ev) ++ " pseed: " ++ show (pvpePSeed ev) ++ " qseed: " ++ show (pvpeQSeed ev) ++ " pgen: " ++ show (pvpePGenCounter ev) ++ " qgen: " ++ show (pvpeQGenCounter ev)) False
              else True
 where mseedlen' = fmap (\ x -> (getPositive x * 8) + getN params) mseedlen

prop_validateUnvG :: CryptoRandomGen g =>
                     g -> ParameterSizes -> ArbHashFunction ->
                     Bool
prop_validateUnvG gen params (HF _ hash) =
  case generateProbablePrimes params gen hash Nothing of
    Left _ -> error "Failed to generate p and q testing unverifiable g generation."
    Right (p, q, _, _) ->
      case generateUnverifiableGenerator p q of
        Nothing -> error "Failed to generate g for p and q (unverifiable)."
        Just g  -> generatorIsValid p q g

prop_validateVerG :: CryptoRandomGen g =>
                     g -> ParameterSizes -> ArbHashFunction -> Word8 ->
                     Bool
prop_validateVerG gen params (HF _ hash) index =
  case generateProbablePrimes params gen hash Nothing of
    Left _ -> error "Failed to generate p and q testing unverifiable g generation."
    Right (p, q, ev, _) ->
      case generateVerifiableGenerator p q ev index of
        Nothing -> error "Failed to generate g for p and q (unverifiable)."
        Just g  -> validateVerifiableGenerator p q ev index g

sampleMsg :: ByteString
sampleMsg = BSC.pack "sample"

test_RFCKGen :: CryptoRandomGen g => g -> Assertion
test_RFCKGen g = assertEqual "" myValue rfcValue
 where
  rfcValue = 0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B
  KValue myValue _ _ = kViaRFC6979 g SHA256 privkey sampleMsg
  --
  q   = 0x4000000000000000000020108A2E0CC0D99F8A5EF
  x   = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
  privkey = PrivateKey (Params (error "p") (error "g") q) x

runRFCTest :: CryptoRandomGen g =>
              PrivateKey ->
              g -> HashFunction -> String ->
              Integer -> Integer -> Integer ->
              [Test]
runRFCTest priv g hash s rfcK rfcR rfcS =
  [ testCase "K correct" (assertEqual "" rfcK myK)
  , testCase "R correct" (assertEqual "" rfcR myR)
  , testCase "S correct" (assertEqual "" rfcS myS) ]
 where
  KValue myK _ _ = kViaRFC6979 g hash priv msg
  Right (Signature myR myS, _) = signMessage' hash kViaRFC6979 g priv msg
  msg = BSC.pack s

a21KeyPriv :: PrivateKey
a21KeyPriv = PrivateKey (Params 0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779 0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD 0x996F967F6C8E388D9E28D01E205FBA957A5698B1) 0x411602CB19A6CCC34494D79D98EF1E7ED5AF25F7

runA21Test :: CryptoRandomGen g =>
              g -> HashFunction -> String ->
              Integer -> Integer -> Integer ->
              [Test]
runA21Test = runRFCTest a21KeyPriv

a22KeyPriv :: PrivateKey
a22KeyPriv = PrivateKey (Params 0x9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44FFE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE235567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA153E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B 0x5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C46A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7 0xF2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F) 0x69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC

runA22Test :: CryptoRandomGen g =>
              g -> HashFunction -> String ->
              Integer -> Integer -> Integer ->
              [Test]
runA22Test = runRFCTest a22KeyPriv

test_RFCA21_1sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_1sample   g = runA21Test g SHA1 "sample" k r s
 where
  k = 0x7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B
  r = 0x2E1A0C2562B2912CAAF89186FB0F42001585DA55
  s = 0x29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5

test_RFCA21_224sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_224sample   g = runA21Test g SHA224 "sample" k r s
 where
  k = 0x562097C06782D60C3037BA7BE104774344687649
  r = 0x4BC3B686AEA70145856814A6F1BB53346F02101E
  s = 0x410697B92295D994D21EDD2F4ADA85566F6F94C1

test_RFCA21_256sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_256sample   g = runA21Test g SHA256 "sample" k r s
 where
  k = 0x519BA0546D0C39202A7D34D7DFA5E760B318BCFB
  r = 0x81F2F5850BE5BC123C43F71A3033E9384611C545
  s = 0x4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89

test_RFCA21_384sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_384sample   g = runA21Test g SHA384 "sample" k r s
 where
  k = 0x95897CD7BBB944AA932DBC579C1C09EB6FCFC595
  r = 0x07F2108557EE0E3921BC1774F1CA9B410B4CE65A
  s = 0x54DF70456C86FAC10FAB47C1949AB83F2C6F7595

test_RFCA21_512sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_512sample   g = runA21Test g SHA512 "sample" k r s
 where
  k = 0x09ECE7CA27D0F5A4DD4E556C9DF1D21D28104F8B
  r = 0x16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B
  s = 0x02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C

test_RFCA21_1test   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_1test   g = runA21Test g SHA1 "test" k r s
 where
  k = 0x5C842DF4F9E344EE09F056838B42C7A17F4A6433
  r = 0x42AB2052FD43E123F0607F115052A67DCD9C5C77
  s = 0x183916B0230D45B9931491D4C6B0BD2FB4AAF088

test_RFCA21_224test   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_224test   g = runA21Test g SHA224 "test" k r s
 where
  k = 0x4598B8EFC1A53BC8AECD58D1ABBB0C0C71E67297
  r = 0x6868E9964E36C1689F6037F91F28D5F2C30610F2
  s = 0x49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F

test_RFCA21_256test   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_256test   g = runA21Test g SHA256 "test" k r s
 where
  k = 0x5A67592E8128E03A417B0484410FB72C0B630E1A
  r = 0x22518C127299B0F6FDC9872B282B9E70D0790812
  s = 0x6837EC18F150D55DE95B5E29BE7AF5D01E4FE160

test_RFCA21_384test   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_384test   g = runA21Test g SHA384 "test" k r s
 where
  k = 0x220156B761F6CA5E6C9F1B9CF9C24BE25F98CD89
  r = 0x854CF929B58D73C3CBFDC421E8D5430CD6DB5E66
  s = 0x91D0E0F53E22F898D158380676A871A157CDA622

test_RFCA21_512test   :: CryptoRandomGen g => g -> [Test]
test_RFCA21_512test   g = runA21Test g SHA512 "test" k r s
 where
  k = 0x65D2C2EEB175E370F28C75BFCDC028D22C7DBE9C
  r = 0x8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0
  s = 0x7C670C7AD72B6C050C109E1790008097125433E8

test_RFCA22_1sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_1sample   g = runA22Test g SHA1 "sample" k r s
 where
  k = 0x888FA6F7738A41BDC9846466ABDB8174C0338250AE50CE955CA16230F9CBD53E
  r = 0x3A1B2DBD7489D6ED7E608FD036C83AF396E290DBD602408E8677DAABD6E7445A
  s = 0xD26FCBA19FA3E3058FFC02CA1596CDBB6E0D20CB37B06054F7E36DED0CDBBCCF

test_RFCA22_224sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_224sample   g = runA22Test g SHA224 "sample" k r s
 where
  k = 0xBC372967702082E1AA4FCE892209F71AE4AD25A6DFD869334E6F153BD0C4D806
  r = 0xDC9F4DEADA8D8FF588E98FED0AB690FFCE858DC8C79376450EB6B76C24537E2C
  s = 0xA65A9C3BC7BABE286B195D5DA68616DA8D47FA0097F36DD19F517327DC848CEC

test_RFCA22_256sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_256sample   g = runA22Test g SHA256 "sample" k r s
 where
  k = 0x8926A27C40484216F052F4427CFD5647338B7B3939BC6573AF4333569D597C52
  r = 0xEACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809
  s = 0x7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53

test_RFCA22_384sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_384sample   g = runA22Test g SHA384 "sample" k r s
 where
  k = 0xC345D5AB3DA0A5BCB7EC8F8FB7A7E96069E03B206371EF7D83E39068EC564920
  r = 0xB2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B
  s = 0x19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B

test_RFCA22_512sample   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_512sample   g = runA22Test g SHA512 "sample" k r s
 where
  k = 0x5A12994431785485B3F5F067221517791B85A597B7A9436995C89ED0374668FC
  r = 0x2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E
  s = 0xD0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351

test_RFCA22_1test   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_1test   g = runA22Test g SHA1 "test" k r s
 where
  k = 0x6EEA486F9D41A037B2C640BC5645694FF8FF4B98D066A25F76BE641CCB24BA4F
  r = 0xC18270A93CFC6063F57A4DFA86024F700D980E4CF4E2CB65A504397273D98EA0
  s = 0x414F22E5F31A8B6D33295C7539C1C1BA3A6160D7D68D50AC0D3A5BEAC2884FAA

test_RFCA22_224test   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_224test   g = runA22Test g SHA224 "test" k r s
 where
  k = 0x06BD4C05ED74719106223BE33F2D95DA6B3B541DAD7BFBD7AC508213B6DA6670
  r = 0x272ABA31572F6CC55E30BF616B7A265312018DD325BE031BE0CC82AA17870EA3
  s = 0xE9CC286A52CCE201586722D36D1E917EB96A4EBDB47932F9576AC645B3A60806

test_RFCA22_256test   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_256test   g = runA22Test g SHA256 "test" k r s
 where
  k = 0x1D6CE6DDA1C5D37307839CD03AB0A5CBB18E60D800937D67DFB4479AAC8DEAD7
  r = 0x8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0
  s = 0x7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E

test_RFCA22_384test   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_384test   g = runA22Test g SHA384 "test" k r s
 where
  k = 0x206E61F73DBE1B2DC8BE736B22B079E9DACD974DB00EEBBC5B64CAD39CF9F91C
  r = 0x239E66DDBE8F8C230A3D071D601B6FFBDFB5901F94D444C6AF56F732BEB954BE
  s = 0x6BD737513D5E72FE85D1C750E0F73921FE299B945AAD1C802F15C26A43D34961

test_RFCA22_512test   :: CryptoRandomGen g => g -> [Test]
test_RFCA22_512test   g = runA22Test g SHA512 "test" k r s
 where
  k = 0xAFF1651E4CD6036D57AA8B2A05CCF1A9D5A40166340ECBBDC55BE10B568AA0AA
  r = 0x89EC4BB1400ECCFF8E7D9AA515CD1DE7803F2DAFF09693EE7FD1353E90A68307
  s = 0xC9F0BDABCC0D880BB137A994CC7F3980CE91CC10FAF529FC46565B15CEA854E1

instance Arbitrary ByteString where
  arbitrary = pack `fmap` arbitrary

prop_verifySig :: CryptoRandomGen g => g -> ParameterSizes -> ByteString -> Bool
prop_verifySig gen sizes msg =
  case generateKeyPair gen sizes of
    Left _ -> False
    Right (pub, priv, _, _) ->
      case signMessage priv msg of
        Left _ -> False
        Right sig -> verifyMessage pub msg sig

data KGen g = KGen (KGenerator g) String

instance CryptoRandomGen g => Arbitrary (KGen g) where
  arbitrary = elements [ KGen kViaRFC6979 "RFC"
                       , KGen kViaExtraRandomBits "Exrta"
                       , KGen kViaTestingCandidates "Testing"]

instance Show (KGen g) where
  show (KGen _ str) = "KGen:" ++ str

instance Arbitrary HashFunction where
  arbitrary = elements [SHA1, SHA224, SHA256, SHA384, SHA512]

prop_verifySig' :: CryptoRandomGen g =>
                   g -> ParameterSizes ->
                   HashFunction -> KGen g ->
                   ByteString ->
                   Bool
prop_verifySig' gen sizes hash (KGen kgen _) msg =
  case generateKeyPair gen sizes of
    Left _ -> False
    Right (pub, priv, _, _) ->
      case signMessage' hash kgen gen priv msg of
        Left _ -> False
        Right (sig, _) -> verifyMessage' hash pub msg sig
