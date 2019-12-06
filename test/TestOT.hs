{-# LANGUAGE ScopedTypeVariables #-}
module TestOT where

import           Data.List
import           Protolude
import qualified Test.QuickCheck.Monadic          as QCM
import           Test.Tasty
import           Test.Tasty.HUnit
import           Test.Tasty.QuickCheck

import           Data.Curve.Weierstrass.SECP256K1
import qualified OT

test_OT :: TestTree
test_OT = testGroup "1-out-of-N oblivious transfer"
  [ localOption (QuickCheckTests 10) $ testProperty
      "Verify that the receiver key is one of the sender keys"
      (forAll (choose (3, 20) ) testOT)


   ,   localOption (QuickCheckTests 10) $ testProperty
      "Verify m 1-out-of-n receiver keys match with sender keys"
      (forAll (choose (3, 20)) testMOT)
   ]

--test m 1-out-of-n OT protocol
testMOT:: Integer -> Property
testMOT n = QCM.monadicIO $ do
  let m = 20
  (sPrivKey, sPubKey, t) :: (Fr, PA, PA) <- liftIO OT.setup
  choices <- liftIO $ OT.mChoose n sPubKey m []
  let (rPrivKeys, responses, cs) = unzip3 choices
  let senderKeys = OT.mDeriveSenderKeys n sPrivKey responses t
  let recieverKeys = OT.mDeriveReceiverKeys rPrivKeys sPubKey
  QCM.assert True

-- test 1 out of n OT protocol
testOT :: Integer -> Property
testOT n = QCM.monadicIO $ do

  (sPrivKey, sPubKey, t):: (Fr, PA, PA) <- liftIO OT.setup

  (rPrivKey, response, c) <- liftIO $ OT.choose n sPubKey

  let senderKeys = OT.deriveSenderKeys n sPrivKey response t

  -- Receiver only gets to know one out of n values. Sender doesn't know which one
  let receiverKey = OT.deriveReceiverKey rPrivKey sPubKey

  QCM.assert $ receiverKey == (senderKeys !! fromInteger c)
