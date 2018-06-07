module OT where

import Protolude hiding (hash, elem)

import           Crypto.Hash
import           Crypto.Random.Types (MonadRandom)
import qualified Crypto.PubKey.ECC.Prim     as ECC
import qualified Crypto.PubKey.ECC.Types    as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import           Crypto.Number.Generate     (generateBetween)
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA
import           Crypto.Number.Serialize    (os2ip)
import qualified Data.ByteArray             as BA
import qualified Data.ByteString            as BS
import Control.Monad.Fail
import Data.List (elem)

-- test 1 out of n OT protocol
testOT :: ECC.Curve -> Integer -> IO Integer
testOT curve n = do

  -- TODO: Leaking only privKey here for testing purposes
  (sPrivKey, sPubKey, t) <- setup curve n

  response <- choose curve n sPubKey

  let senderKeys = deriveSenderKeys curve n (sPrivKey, sPubKey) response t
  let verifierKey = deriveVerifierKey curve n sPubKey response

  unless (verifierKey `elem` senderKeys) $
    fail "Unsuccessful key agreement"

  pure verifierKey

setup :: (MonadRandom m, MonadFail m) => ECC.Curve -> Integer -> m (Integer, ECC.Point, ECC.Point)
setup curve n = do
  -- 1. Sender samples y <- Zp and computes S = yB and T = yS
  (pubKey, privKey) <- ECC.generate curve
  let sPrivKey = ECDSA.private_d privKey
  let sPubKey = ECDSA.public_q pubKey
  let t = ECC.pointMul curve sPrivKey sPubKey

  -- 2. S sends S to R, who aborts if S doesn't belong to G
  unless (ECC.isPointValid curve sPubKey) $
    fail "Invalid sPubKey from sender"

  pure (sPrivKey, sPubKey, t)


choose :: (MonadRandom m, MonadFail m) => ECC.Curve -> Integer -> ECC.Point -> m ECC.Point
choose curve n sPubKey = do
  -- In parallel for all i in [m]
  -- 1. Reciever samples x <- Zp and computes Response
  c <- generateBetween 0 n
  -- Sender creates public and private keys
  (pubKey, privKey) <- ECC.generate curve
  let x = ECDSA.private_d privKey

  let cS = ECC.pointMul curve c sPubKey
  let xB = ECDSA.public_q pubKey
  let response = ECC.pointAdd curve cS xB
  --
  -- 2. Fail if the response is not a valid point in the curve
  unless (ECC.isPointValid curve response) $
    fail "Invalid response from verifier"

  pure response

deriveSenderKeys :: ECC.Curve -> Integer -> (Integer, ECC.Point) -> ECC.Point -> ECC.Point -> [Integer]
deriveSenderKeys curve n (sPrivKey, sPubKey) response t = deriveSenderKey <$> [0..n-1]
 where
    deriveSenderKey j = hashPoint curve (ECC.pointAdd curve yR (ECC.pointNegate curve (jT j)))
    yR = ECC.pointMul curve sPrivKey response
    jT j = ECC.pointMul curve j t

deriveVerifierKey :: ECC.Curve -> Integer -> ECC.Point -> ECC.Point -> Integer
deriveVerifierKey curve x sPubKey response = hashPoint curve (ECC.pointMul curve x sPubKey)

secp256k1Curve :: ECC.Curve
secp256k1Curve = ECC.getCurveByName ECC.SEC_p256k1

hashPoint :: ECC.Curve -> ECC.Point -> Integer
hashPoint curve ECC.PointO      = oracle curve ""
hashPoint curve (ECC.Point x y) = oracle curve (show x <> show y)

oracle :: ECC.Curve -> BS.ByteString -> Integer
oracle curve x = os2ip (sha256 x) `mod` ecc_n
  where
    ecc_n = ECC.ecc_n (ECC.common_curve curve)

-- | Secure cryptographic hash function
sha256 :: BS.ByteString -> BS.ByteString
sha256 bs = BA.convert (hash bs :: Digest SHA3_256)
