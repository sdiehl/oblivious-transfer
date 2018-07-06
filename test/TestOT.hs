module TestOT where

import           Protolude
import           Data.List 
import qualified Test.QuickCheck.Monadic as QCM
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck
import qualified Crypto.PubKey.ECC.Prim     as ECC
import qualified Crypto.PubKey.ECC.Types    as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC

import qualified OT

secp256k1Curve :: ECC.Curve
secp256k1Curve = ECC.getCurveByName ECC.SEC_p256k1

test_OT :: TestTree
test_OT = testGroup "1-out-of-N oblivious transfer"
  [ localOption (QuickCheckTests 10) $ testProperty
      "Verify that the receiver key is one of the sender keys"
      (forAll (choose (3, 20) )(testOT secp256k1Curve))

  
   ,   localOption (QuickCheckTests 10) $ testProperty
      "Verify m 1-out-of-n receiver keys match with sender keys"
      (forAll (choose (3, 20)) (testMOT secp256k1Curve))
   ]

--test m 1-out-of-n OT protocol
testMOT:: ECC.Curve -> Integer -> Property
testMOT curve n = QCM.monadicIO $ do
  let m = 20
  (sPrivKey, sPubKey, t) <- liftIO $ OT.setup curve
  choices <- liftIO $OT.mChoose curve n sPubKey m []
  let (rPrivKeys, responses, cs) = OT.unzip3 choices
  let senderKeys = OT.mDeriveSenderKeys curve n sPrivKey responses t
  let recieverKeys = OT.mDeriveReceiverKeys curve rPrivKeys sPubKey
  QCM.assert True

-- test 1 out of n OT protocol
testOT :: ECC.Curve -> Integer -> Property
testOT curve n = QCM.monadicIO $ do

  (sPrivKey, sPubKey, t) <- liftIO $ OT.setup curve

  (rPrivKey, response, c) <- liftIO $ OT.choose curve n sPubKey

  let senderKeys = OT.deriveSenderKeys curve n sPrivKey response t

  -- Receiver only gets to know one out of n values. Sender doesn't know which one
  let receiverKey = OT.deriveReceiverKey curve rPrivKey sPubKey

  QCM.assert $ receiverKey == (senderKeys !! fromInteger c)
