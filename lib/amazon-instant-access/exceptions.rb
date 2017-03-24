module AmazonInstantAccess

  # Generic error raised during request authentication
  class AuthenticationError < Exception; end

  # Raised when the request is missing a required header
  class MissingHeaderError < AuthenticationError; end

  # Raised when the request has a malformed authorization header
  class MalformedAuthHeaderError < AuthenticationError; end

  # Raised when the request is expired
  class ExpiredRequestError < AuthenticationError; end

  # Raised when the request has an unknown public key
  class UnknownPublicKeyError <AuthenticationError; end

  # Raised When the request has an unsupported hashing algorithm
  class UnsupportedAlgorithmError < AuthenticationError; end

  # Raised when the signature does not match the computed/expected one
  class IncorrectSignatureError < AuthenticationError; end

end
