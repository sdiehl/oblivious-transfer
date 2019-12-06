module OT
( setup
, choose
, deriveSenderKeys
, deriveReceiverKey
, mDeriveSenderKeys
, mDeriveReceiverKeys
--, unzip3
, mChoose
) where

import           Protolude            hiding (fromStrict, hash)

import           Control.Monad.Fail
import           Control.Monad.Random (MonadRandom, getRandom, getRandomR)
import qualified Data.ByteArray       as BA
import qualified Data.ByteString      as BS
import           Data.ByteString.Lazy (fromStrict)
import           Data.Curve
import           Data.Digest.Pure.SHA (integerDigest, sha256)
import           Data.Field.Galois    (PrimeField (..))
import           Data.List            ((!!))

genKeys :: (Curve f c e q r, MonadRandom m) => m (r, Point f c e q r)
genKeys = do
  sk <- getRandom
  let pk = mul gen sk
  return (sk, pk)

-- | Setup: Only once, independently of the number of OT messages *m*.
setup :: (Curve f c e q r, MonadRandom m) => m (r, Point f c e q r, Point f c e q r)
setup = do
  -- 1. Sender samples y <- Zp and computes S = yB and T = yS
  (sPrivKey, sPubKey) <- genKeys
  let t = mul sPubKey sPrivKey

  pure (sPrivKey, sPubKey, t)

-- | Choose: In parallel for all OT messages.
choose :: (Curve f c e q r, MonadRandom m) => Integer -> Point f c e q r -> m (r, Point f c e q r, Integer)
choose n sPubKey = do
  -- 1. Receiver samples x <- Zp and computes Response
  c <- getRandomR (0, n - 1)
  (rPrivKey, xB) <- genKeys

  let cS = mul sPubKey (fromInteger c)
  let response = add cS xB

  pure (rPrivKey, response, c)


-- | Call 'choose' 'm' times to create a list of three lists
-- Return lists of private keys, responses and choice bit
mChoose
  :: (Eq t, Num t, Curve f c e q r, MonadRandom m)
     => Integer
     -> Point f c e q r
     -> t
     -> [(r, Point f c e q r, Integer)]
     -> m [(r, Point f c e q r, Integer)]
mChoose n sPubKey 0 accum = return accum
mChoose n sPubKey m accum = do
  a <- choose n sPubKey
  b <- mChoose n sPubKey (m-1) accum
  let accum = a : b
  return accum

-- | Sender's key derivation from his private key and receiver's response
-- In parallel for all OT messages
deriveSenderKeys :: Curve f c e q r => Integer -> r -> Point f c e q r -> Point f c e q r -> [r]
deriveSenderKeys n sPrivKey response t = deriveSenderKey <$> [0..n-1]
 where
    deriveSenderKey j = hashPoint (add yR (inv (jT j)))
    yR = mul response sPrivKey
    jT = mul t . fromInteger


-- | Fold 'm' calls of 'deriveSenderKeys'
mDeriveSenderKeys
  :: Curve f c e q r
  => Integer
  -> r
  -> [Point f c e q r]
  -> Point f c e q r
  -> [[r]]
mDeriveSenderKeys n sPrivKey responses t = mDeriveSenderKeys' <$> responses
  where mDeriveSenderKeys' response = deriveSenderKeys n sPrivKey response t


-- | Receiver's key derivation from his private key and sender's public key
-- In parallel for all OT messages
deriveReceiverKey :: Curve f c e q r => r -> Point f c e q r -> r
deriveReceiverKey rPrivKey sPubKey = hashPoint (mul sPubKey rPrivKey)


-- | Fold 'm' calls of 'deriveReceiverKeys'
mDeriveReceiverKeys
  :: Curve f c e q r
  => [r]
  -> Point f c e q r
  -> [r]
mDeriveReceiverKeys rPrivKeys sPubKey = deriveReceiverKey'  <$> rPrivKeys
  where deriveReceiverKey' rPrivKey = deriveReceiverKey rPrivKey sPubKey

hashPoint :: Curve f c e q r => Point f c e q r -> r
hashPoint p | p == id   = oracle ""
            | otherwise = oracle (show p)

-- | Output unpredictable but deterministic random values
oracle :: PrimeField f => ByteString -> f
oracle = fromInteger . integerDigest . sha256 . fromStrict
