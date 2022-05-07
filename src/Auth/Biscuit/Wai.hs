{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Auth.Biscuit.Wai
  ( BiscuitConfig (..)
  , biscuitAuth
  , checkBiscuit
  , biscuit
  , extractFromAuthHeader
  , extractionError
  , parseError
  , authorizationError
  ) where

import           Debug.Trace

import           Auth.Biscuit              (AuthorizationSuccess, Authorizer,
                                            Biscuit, OpenOrSealed, ParseError,
                                            ParserConfig, Verified,
                                            authorizeBiscuit, parseWith)
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.Vault.Lazy           as Vault
import           Network.HTTP.Types.Status (forbidden403,
                                            internalServerError500,
                                            unauthorized401)
import           Network.Wai
import           System.IO.Unsafe          (unsafePerformIO)
import           Web.Twain                 (status, text)
import           Web.Twain.Types           (ResponderM (..), RouteAction (..))

data BiscuitConfig e
  = BiscuitConfig
  { parserConfig             :: ParserConfig IO
  -- ^ how to parse a serialized biscuit (this includes public key and revocation checks)
  , extractSerializedBiscuit :: Request -> Either e ByteString
  -- ^ how to extract the serialized biscuit from the request
  , onExtractionError        :: e -> IO Response
  -- ^ what to do when the biscuit cannot be extracted from the request
  , onParseError             :: ParseError -> IO Response
  -- ^ what to do when the biscuit cannot be parsed
  }

tokenKey :: Vault.Key (Biscuit OpenOrSealed Verified)
tokenKey = unsafePerformIO Vault.newKey
{-# NOINLINE tokenKey #-}

biscuitAuth :: BiscuitConfig e -> Middleware
biscuitAuth BiscuitConfig{..} app request respond = do
  let tokenBytes = extractSerializedBiscuit request
   in case tokenBytes of
        Left e   -> respond =<< onExtractionError e
        Right bs -> do
          tokenRes <- parseWith parserConfig bs
          case tokenRes of
            Left e  -> respond =<< onParseError e
            Right t -> do
              let oldVault = vault request
                  newVault = Vault.insert tokenKey t oldVault
               in app (request { vault = newVault }) respond

checkBiscuit :: Request
             -> Authorizer
             -> (AuthorizationSuccess -> IO Response)
             -> IO Response
checkBiscuit request authorizer handler = do
  let onError = pure $ responseLBS internalServerError500 mempty mempty
  case Vault.lookup tokenKey $ vault request of
    Nothing -> onError
    Just token -> do
      result <- authorizeBiscuit token authorizer
      case result of
        Left _  -> onError
        Right s -> handler s

biscuit :: Authorizer
        -> ResponderM AuthorizationSuccess
biscuit authorizer = ResponderM $ \request -> do
  let mToken = Vault.lookup tokenKey $ vault request
  case mToken of
    Nothing -> pure $ Left $ Respond $ status internalServerError500 $ text "Biscuit not found"
    Just token -> do
      result <- authorizeBiscuit token authorizer
      case result of
        Left _ -> pure $ Left $ Respond $ status forbidden403 $ text "Biscuit failed authorization"
        Right s -> pure $ Right (s, request)

extractFromAuthHeader :: Request
                      -> Either String ByteString
extractFromAuthHeader request = do
  let note e = maybe (Left e) Right
  authHeader <- note "Missing Authorization header" . lookup "Authorization" $ requestHeaders request
  note "Not a Bearer token" $ BS.stripPrefix "Bearer " authHeader

extractionError :: Response
extractionError = status unauthorized401 $ text "Missing biscuit"

parseError :: Response
parseError = status unauthorized401 $ text "Invalid biscuit"

authorizationError :: Response
authorizationError = status forbidden403 $ text "Unauthorized biscuit"
