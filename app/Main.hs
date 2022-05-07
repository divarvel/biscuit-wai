{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE TypeApplications  #-}
module Main where

import           Auth.Biscuit
import           Auth.Biscuit.Wai
import           Data.Maybe               (fromJust)
import           Network.Wai.Handler.Warp (run)
import           Web.Twain

config :: BiscuitConfig String
config = BiscuitConfig
  { parserConfig = ParserConfig
     { encoding = UrlBase64
     , isRevoked = const $ pure False
     , getPublicKey = const $ fromJust $ parsePublicKeyHex "9aabe4e1ea8fb976e21c8ad8a1a94378e56986fb428048d5d16b64427359475b"
     }
  , extractSerializedBiscuit = extractFromAuthHeader
  , onExtractionError = const $ pure extractionError
  , onParseError = const $ pure parseError
  }

main :: IO ()
main = do
  putStrLn "Running on port 8080"
  run 8080 $
    foldr ($)
      (notFound missing)
      [ get "/" index
      , biscuitAuth config . get "hello/:id" echo
      ]

index :: ResponderM a
index = send $ html "Hello World!"

echo :: ResponderM a
echo = do
  userId <- param @Int "id"
  result <- biscuit [authorizer|allow if user(${userId});|]
  send $ html $ "Hello, you"

missing :: ResponderM a
missing = send $ html "Not found..."
