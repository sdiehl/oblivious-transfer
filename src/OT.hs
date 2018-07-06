module OT
( setup
, choose
, deriveSenderKeys
, deriveReceiverKey
, mDeriveSenderKeys
, mDeriveReceiverKeys
, unzip3
, mChoose
) where

import Protolude hiding (hash)

import           Crypto.Hash
import           Crypto.Random.Types (MonadRandom)
import qualified Crypto.PubKey.ECC.Prim     as ECC
import qualified Crypto.PubKey.ECC.Types    as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import           Crypto.Number.Generate     (generateMax)
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA
import           Crypto.Number.Serialize    (os2ip)
import qualified Data.ByteArray             as BA
import qualified Data.ByteString            as BS
import Control.Monad.Fail
import           GHC.List  ((!!))  


-- Conveniences to be removed
curve :: ECC.Curve
curve = ECC.getCurveByName ECC.SEC_p256k1

g :: ECC.Point
g = ECC.ecc_g $ ECC.common_curve curve

testPoint1 :: ECC.Point
testPoint1 = ECC.pointMul curve 4 g




-- | Setup: Only once, independently of the number of OT messages *m*.
setup :: (MonadRandom m, MonadFail m) => ECC.Curve -> m (Integer, ECC.Point, ECC.Point)
setup curve = do
  -- 1. Sender samples y <- Zp and computes S = yB and T = yS
  (sPubKey, sPrivKey) <- bimap ECDSA.public_q ECDSA.private_d <$> ECC.generate curve
  let t = ECC.pointMul curve sPrivKey sPubKey

  -- 2. S sends S to R, who aborts if S doesn't belong to G
  unless (ECC.isPointValid curve sPubKey) $
    fail "Invalid sPubKey from sender"

  pure (sPrivKey, sPubKey, t)


-- | Choose: In parallel for all OT messages.
choose :: (MonadRandom m, MonadFail m) => ECC.Curve -> Integer -> ECC.Point -> m (Integer, ECC.Point, Integer)
choose curve n sPubKey = do
  -- 1. Receiver samples x <- Zp and computes Response
  c <- generateMax (n - 1)
  rPrivKey <- ECDSA.private_d . snd <$> ECC.generate curve

  let cS = ECC.pointMul curve c sPubKey
  let xB = ECC.pointBaseMul curve rPrivKey
  let response = ECC.pointAdd curve cS xB

  -- 2. Fail if the response is not a valid point in the curve
  unless (ECC.isPointValid curve response) $
    fail "Invalid response from verifier"

  pure (rPrivKey, response, c)


mChoose
  :: (Eq t, Num t, MonadRandom m, MonadFail m) =>
     ECC.Curve
     -> Integer
     -> ECC.Point
     -> t
     -> [(Integer, ECC.Point, Integer)]
     -> m [(Integer, ECC.Point, Integer)]

mChoose curve n sPubKey 0 accum = return accum
mChoose curve n sPubKey m accum = do 
  a <- choose curve n sPubKey
  b <- mChoose curve (n) sPubKey (m-1) accum
  let accum = a : b 
  return (accum)

unzip3 :: Foldable t => t (a1, a2, a3) -> ([a1], [a2], [a3])
unzip3 = foldr (\(a,b,c) ~(as,bs,cs) -> (a:as,b:bs,c:cs)) ([],[],[])

mDeriveSenderKeys
  :: ECC.Curve
  -> Integer 
  -> Integer 
  -> [ECC.Point] 
  -> ECC.Point  
  -> [[Integer]]
mDeriveSenderKeys curve n sPrivKey responses t = mDeriveSenderKeys' <$> responses
  where mDeriveSenderKeys' response = deriveSenderKeys curve n sPrivKey response t 


-- | Sender's key derivation from his private key and receiver's response
-- In parallel for all OT messages
deriveSenderKeys :: ECC.Curve -> Integer -> Integer -> ECC.Point -> ECC.Point -> [Integer]
deriveSenderKeys curve n sPrivKey response t = deriveSenderKey <$> [0..n-1]
 where
    deriveSenderKey j = hashPoint curve (ECC.pointAdd curve yR (ECC.pointNegate curve (jT j)))
    yR = ECC.pointMul curve sPrivKey response
    jT j = ECC.pointMul curve j t

-- | Receiver's key derivation from his private key and sender's public key
-- In parallel for all OT messages
deriveReceiverKey :: ECC.Curve -> Integer -> ECC.Point -> Integer
deriveReceiverKey curve rPrivKey sPubKey = hashPoint curve (ECC.pointMul curve rPrivKey sPubKey)

mDeriveReceiverKeys
  :: ECC.Curve
  -> [Integer] 
  -> ECC.Point  
  -> [Integer]
mDeriveReceiverKeys curve rPrivKeys sPubKey = deriveReceiverKey'  <$> rPrivKeys
  where deriveReceiverKey' rPrivKey = deriveReceiverKey curve rPrivKey sPubKey

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

