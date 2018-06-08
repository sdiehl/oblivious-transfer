module OT
( setup
, choose
, deriveSenderKeys
, deriveReceiverKey
) where

import Protolude hiding (hash)

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

setup :: (MonadRandom m, MonadFail m) => ECC.Curve -> m (Integer, ECC.Point, ECC.Point)
setup curve = do
  -- 1. Sender samples y <- Zp and computes S = yB and T = yS
  (sPubKey, sPrivKey) <- bimap ECDSA.public_q ECDSA.private_d <$> ECC.generate curve
  let t = ECC.pointMul curve sPrivKey sPubKey

  -- 2. S sends S to R, who aborts if S doesn't belong to G
  unless (ECC.isPointValid curve sPubKey) $
    fail "Invalid sPubKey from sender"

  pure (sPrivKey, sPubKey, t)


-- In parallel for all i in [m]
choose :: ECC.Curve -> Integer -> ECC.Point -> IO (Integer, ECC.Point)
choose curve n sPubKey = do
  -- 1. Reciever samples x <- Zp and computes Response
  c <- generateBetween 0 (n - 1)
  -- Sender creates public and private keys
  rPrivKey <- ECDSA.private_d . snd <$> ECC.generate curve

  let cS = ECC.pointMul curve c sPubKey
  let xB = ECC.pointBaseMul curve rPrivKey
  let response = ECC.pointAdd curve cS xB
  --
  -- 2. Fail if the response is not a valid point in the curve
  unless (ECC.isPointValid curve response) $
    fail "Invalid response from verifier"

  pure (rPrivKey, response)

deriveSenderKeys :: ECC.Curve -> Integer -> (Integer, ECC.Point) -> ECC.Point -> ECC.Point -> [Integer]
deriveSenderKeys curve n (sPrivKey, sPubKey) response t = deriveSenderKey <$> [0..n-1]
 where
    deriveSenderKey j = hashPoint curve (ECC.pointAdd curve yR (ECC.pointNegate curve (jT j)))
    yR = ECC.pointMul curve sPrivKey response
    jT j = ECC.pointMul curve j t

deriveReceiverKey :: ECC.Curve -> Integer -> ECC.Point -> Integer
deriveReceiverKey curve x sPubKey = hashPoint curve (ECC.pointMul curve x sPubKey)

secp256k1Curve :: ECC.Curve
secp256k1Curve = ECC.getCurveByName ECC.SEC_p256k1

hashPoint :: ECC.Curve -> ECC.Point -> Integer
hashPoint curve ECC.PointO      = oracle curve ""
hashPoint curve (ECC.Point x y) = oracle curve (show x <> show y)

-- | Outputs unpredictable but deterministic random values
oracle :: ECC.Curve -> BS.ByteString -> Integer
oracle curve x = os2ip (sha256 x) `mod` ecc_n
  where
    ecc_n = ECC.ecc_n (ECC.common_curve curve)

-- | Secure cryptographic hash function
sha256 :: BS.ByteString -> BS.ByteString
sha256 bs = BA.convert (hash bs :: Digest SHA3_256)
