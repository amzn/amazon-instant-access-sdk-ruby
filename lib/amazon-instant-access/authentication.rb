require 'logger'
require 'openssl'
require 'time'
require 'uri'

require 'amazon-instant-access/exceptions'

module AmazonInstantAccess

  # Handles request authentication for Amazon Instant Access integration
  #
  # @author Amazon.com LLC
  #
  class Authentication

    AUTHORIZATION_HEADER = 'Authorization'
    X_AMZ_DATE_HEADER = 'x-amz-date'
    DTA1_HMAC_SHA256 = 'DTA1-HMAC-SHA256'
    TIME_TOLERANCE = 15 * 60  # 15 minutes
    DATE_FORMAT = '%Y%m%d'
    DATETIME_FORMAT = '%Y%m%dT%H%M%SZ'
    HEADER_REGEX = '(\S+) SignedHeaders=(\S+), Credential=(\S+), Signature=([\S&&[^,]]+)'
    DEFAULT_LOG_PATH = 'amazon_instant_access_auth.log'

    # Initialize the AIA authentication instance
    #
    # @param credentials [Hash] vendor credentials (public key => private key)
    # @param logger [Logger] vendor's custom logger object
    #
    # @raise [ArgumentError] invalid or empty credentials was provided
    #
    # @return [void]
    #
    def initialize(credentials, logger=nil)
      if credentials.nil? || credentials.empty? || credentials.class != Hash
        raise ArgumentError.new 'Invalid or empty credentials'
      end

      # Convert all symbols to strings
      @credentials = {}
      credentials.each do |key, value|
        @credentials[key.to_s] = value.to_s
      end

      @logger = logger.nil? ? Logger.new(DEFAULT_LOG_PATH) : logger
    end

    # Verify the request to ensure that it is initiated by Amazon
    #
    # @param method [String] HTTP method of the request
    # @param url [String] full URL of the request
    # @param body [String] raw body (payload) of the request
    # @param headers [Object] request headers which must allow case-insensitive, string key based access
    #
    # @raise [MissingHeaderError] the request is missing a required header
    # @raise [ExpiredRequestError] the request is expired
    # @raise [MalformedAuthHeaderError] the request has a malformed authorization header
    # @raise [UnknownPublicKeyError] the request has an unknown public key
    # @raise [UnsupportedAlgorithmError] the request has an unsupported hashing algorithm
    # @raise [IncorrectSignatureError] the signature does not match the computed/expected one
    #
    # @return [void]
    #
    def verify_request(method, url, body, headers)
      amz_date_header = headers[X_AMZ_DATE_HEADER]
      if amz_date_header.nil?
        @logger.error "Received a request with missing header: #{X_AMZ_DATE_HEADER}"
        raise MissingHeaderError.new X_AMZ_DATE_HEADER
      end

      auth_header = headers[AUTHORIZATION_HEADER]
      if auth_header.nil?
        @logger.error "Received a request with missing header: #{AUTHORIZATION_HEADER}"
        raise MissingHeaderError.new AUTHORIZATION_HEADER
      end

      amz_date = Time.parse(amz_date_header)
      if (Time.now.utc - amz_date.utc).to_i.abs > TIME_TOLERANCE
        error_message = "Received an expired request with x-amz-date: #{amz_date}"
        @logger.error error_message
        raise ExpiredRequestError.new error_message
      end

      regex_match = auth_header.match(Regexp.new(HEADER_REGEX))
      if regex_match.nil? || regex_match.length != 5
        @logger.error "Received a request with bad authorization header: #{auth_header}"
        raise MalformedAuthHeaderError.new auth_header
      end

      hash_algorithm = regex_match[1].upcase
      signed_headers = regex_match[2]
      credential = regex_match[3].split('/')
      signature = regex_match[4]

      if credential.length != 2
        @logger.error "Received a request with malformed credential: #{regex_match[3]}"
        raise MalformedAuthHeaderError.new auth_header
      end
      public_key = credential[0]
      secret_key = @credentials[public_key]
      if secret_key.nil?
        @logger.error "Received a request with an unknown public key: #{public_key}"
        raise UnknownPublicKeyError.new public_key
      end

      canonical_headers = []
      signed_headers.split(';').sort_by(&:downcase).each do |key|
        value = headers[key]
        if value.nil?
          raise MissingHeaderError.new key
        end
        canonical_headers << "#{key.downcase.gsub('/\s+/', ' ')}:#{value.gsub('/\s+/', ' ')}"
      end
      url_path = url.nil? ? '': URI.parse(url).path

      # TODO expand when additional hashing algorithms need to be supported
      @logger.info "Attempting to compute signature using hash algorithm: #{hash_algorithm} ..."
      arguments = [method.upcase, url_path, body, canonical_headers, signed_headers, amz_date, secret_key]

      if hash_algorithm == DTA1_HMAC_SHA256
        computed_signature = get_signature_sha256(*arguments)
      else
        @logger.error "Received a request with an unsupported hash algorithm: #{hash_algorithm}"
        raise UnsupportedAlgorithmError.new hash_algorithm
      end

      @logger.info "Computed signature: #{computed_signature}"
      if signature != computed_signature
        error_message = "Rejected request with signature '#{signature}' (expected: '#{computed_signature}')"
        @logger.error error_message
        raise IncorrectSignatureError.new error_message
      end
    end

    # Compute the signature using the request headers via HMAC SHA256
    #
    # @param method [String] HTTP method of the request
    # @param path [String] request URL resource path
    # @param body [String] request body (payload)
    # @param canon_headers [String] canonical headers
    # @param signed_headers [String] list of signed headers
    # @param amz_date [String] Amazon timestamp on the request
    # @param secret_key [String] vendor's secret key
    #
    # @raise [MissingHeaderError] when a header is missing in the request
    #
    # @return [String] signature computed via HMAC SHA256
    #
    def get_signature_sha256(method, path, body, canon_headers, signed_headers, amz_date, secret_key)
      sha256 = OpenSSL::Digest.new('sha256')

      canonical_request = [
          method,
          path == '' ? "/\n" : path + "\n",
          canon_headers.join("\n") + "\n",
          signed_headers,
          sha256.hexdigest(body.nil? ? '': body)
      ].join("\n")

      string_to_sign = [
          DTA1_HMAC_SHA256,
          amz_date.strftime(DATETIME_FORMAT) + "\n",
          sha256.hexdigest(canonical_request)
      ].join("\n")

      timed_key = OpenSSL::HMAC.digest(sha256, secret_key, amz_date.strftime(DATE_FORMAT))
      OpenSSL::HMAC.hexdigest(sha256, timed_key, string_to_sign)
    end

  end

end