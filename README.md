<p align="center">
  <a href="http://www.adjoint.io"><img src="https://www.adjoint.io/assets/logos/logo-small.png" width="250"/></a>
</p>

[![CircleCI](https://circleci.com/gh/adjoint-io/oblivious-transfer.svg?style=svg)](https://circleci.com/gh/adjoint-io/oblivious-transfer)

Oblivious Transfer (OT) is a cryptographic primitive in which a sender transfers some of potentially many pieces of information to a receiver.
The sender doesn't know which pieces of information have been transferred.

1-out-of-2 OT
-------------

In its most basic form, the sender has two secret messages as inputs, _m<sub>0</sub>_ and _m<sub>1</sub>_; the receiver has a choice bit _c_ as input.
At the end of the 1-out-of-2 OT protocol, the receiver should only learn message _M<sub>c</sub>_, while the sender should not
learn the value of the receiver's input _c_.

The protocol is defined for elliptic curves over finite fields _E(F<sub>q</sub>)_. The set of points _E(F<sub>q</sub>)_ is a finite abelian group.
It works as follows:

1. Alice samples a random _a_ and computes _A = aG_. Sends _A_ to Bob
2. Bob has a choice _c_. He samples a random _b_.
    - If _c_ is 0, then he computes B = bG.
    - If _c_ is 1, then he computes B = A + bG.

  Sends B to Alice

3. Alice derives two keys:
    - _K<sub>0</sub> = aB_
    - _K<sub>1</sub> = a(B - A)_

  It's easy to check that Bob can derive the key _K<sub>c</sub>_ corresponding to his choice bit, but cannot compute the other one.

1-out-of-N OT
=============

The 1-out-of-N oblivious transfer protocol is a natural generalization of the 1-out-of-2 OT protocol,
in which the sender has a vector of messages (_M<sub>0</sub>, ..., M<sub>n-1</sub>_). The receiver only has a choice _c_.

We implement a protocol for *random* OT, where the sender, Alice, outputs _n_ random keys and the receiver, Bob, only learns one of them.
It consists on three parts:

**Setup**

Alice samples _a ∈ Z<sub>p</sub>_ and computes _A = aG_ and _T = aA_, where _G_ and _p_ are the generator and the order of the curve, respectively.
She sends _A_ to Bob, who aborts if _A_ is not a valid point in the curve.

**Choose**

Bob takes his choice _c ∈ Z<sub>n</sub>_, samples _b ∈ Z<sub>p</sub>_ and replies _R = cA + bG_. Alice aborts if _R_ is not a valid point in the curve.

**Key derivation**

1. For all _e ∈ Z<sub>n</sub>_, Alice computes _k<sub>e</sub> = aR - eT_. She now has a vector of keys _(k<sub>0</sub>, ..., k<sub>n-1</sub>)_.

2. Bob computes _k<sub>R</sub> = bA_.

We can see that the key _k<sub>e</sub> = aR - eT = abG + (c - e)T_. If _e = c_, then _k<sub>c</sub> = abG = bA = k<sub>R</sub>_.
Therefore, _k<sub>R</sub> = k<sub>c</sub>_ if both parties are honest.

```haskell
testOT :: ECC.Curve -> Integer -> IO Bool
testOT curve n = do

  -- Alice sets up the procotol
  (sPrivKey, sPubKey, t) <- OT.setup curve

  -- Bob picks a choice bit 'c'
  (rPrivKey, response, c) <- OT.choose curve n sPubKey

  -- Alice computes a set of n keys
  let senderKeys = OT.deriveSenderKeys curve n sPrivKey response t

  -- Bob only gets to know one out of n keys. Alice doesn't know which one
  let receiverKey = OT.deriveReceiverKey curve rPrivKey sPubKey

  pure $ receiverKey == (senderKeys !! fromInteger c)
```

------------

**References**:

1.  Chou, T. and Orlandi, C. "The Simplest Protocol for Oblivious Transfer" Technische Universiteit Eindhoven and Aarhus University


**Notation**:

_k_: Lower-case letters are scalars. <br />
_P_: Upper-case letters are points in an elliptic curve. <br />
_kP_: Multiplication of a point P with a scalar k over an elliptic curve defined over a finite field modulo a prime number.

License
-------

```
Copyright 2018 Adjoint Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
