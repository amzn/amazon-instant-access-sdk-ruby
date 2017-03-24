require 'amazon-instant-access'

describe AmazonInstantAccess::Authentication do

  before(:each) do
    @credentials = {'KEYID' => 'SECRETKEY'}
    @method = 'GET'
    @url = 'http://amazon.com'
    @body = 'body'
    @headers = {}
    allow(Time).to receive(:now).and_return(Time.parse('20110909T233600Z'))
  end

  def auth
    return AmazonInstantAccess::Authentication.new(@credentials)
  end

  def request
    return @method, @url, @body, @headers
  end

  it 'should raise built-in ArgumentError on empty credentials on initialization' do
    expect {AmazonInstantAccess::Authentication.new({})}.to raise_error(ArgumentError)
    expect {AmazonInstantAccess::Authentication.new(nil)}.to raise_error(ArgumentError)
  end

  it 'should raise AmazonInstantAccess::MissingHeaderError on missing x-amz-date header' do
    @headers = {}
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::MissingHeaderError)
  end

  it 'should raise AmazonInstantAccess::MissingHeaderError on missing authorization header' do
    @headers = {'x-amz-date' => '20110909T233600Z'}
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::MissingHeaderError)
  end

  it 'should raise AmazonInstantAccess::ExpiredRequestError on expired requests (late by years)' do
    @headers = {'Authorization' => 'foo', 'x-amz-date' => '19990909'}
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::ExpiredRequestError)
  end

  it 'should raise AmazonInstantAccess::ExpiredRequestError on expired requests (late by 1 minute)' do
    @headers = {'Authorization' => 'foo', 'x-amz-date' => '20110909T235200Z'}
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::ExpiredRequestError)
  end

  it 'should raise AmazonInstantAccess::MalformedAuthHeaderError on bad authorization headers' do
    @headers = {'Authorization' => 'foo', 'x-amz-date' => '20110909T233600Z'}
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::MalformedAuthHeaderError)
  end

  it 'should raise AmazonInstantAccess::MalformedAuthHeaderError on malformed credential' do
    @headers = {
        'Authorization' => %W(
            #{AmazonInstantAccess::Authentication::DTA1_HMAC_SHA256}
            SignedHeaders=content-type;x-amz-date,
            Credential=MALFORMED_CREDENTIAL,
            Signature=4d2f81ea2cf8d6963f8176a22eec4c65ae95c63502326a7c148686da7d50f47e
        ).join(' '),
        'x-amz-date' => '20110909T233600Z',
    }
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::MalformedAuthHeaderError)
  end

  it 'should raise AmazonInstantAccess::UnknownPublicKeyError on unknown public key' do
    @headers = {
        'Authorization' => %W(
            #{AmazonInstantAccess::Authentication::DTA1_HMAC_SHA256}
            SignedHeaders=content-type;x-amz-date,
            Credential=UNKNOWN_PUBLIC_KEY/20110909,
            Signature=4d2f81ea2cf8d6963f8176a22eec4c65ae95c63502326a7c148686da7d50f47e
        ).join(' '),
        'x-amz-date' => '20110909T233600Z',
        'content-type' => 'application/json'
    }
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::UnknownPublicKeyError)
  end

  it 'should raise AmazonInstantAccess::UnsupportedAlgorithmHeader on unsupported hash algorithm' do
    @headers = {
        'Authorization' => %W(
            UNSUPPORTED_HASH_ALGORITHM
            SignedHeaders=content-type;x-amz-date,
            Credential=KEYID/20110909,
            Signature=4d2f81ea2cf8d6963f8176a22eec4c65ae95c63502326a7c148686da7d50f47e
        ).join(' '),
        'x-amz-date' => '20110909T233600Z',
        'content-type' => 'application/json'
    }
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::UnsupportedAlgorithmError)
  end

  it 'should raise AmazonInstantAccess::IncorrectSignatureError on incorrect signature' do
    @headers = {
        'Authorization' => %W(
            #{AmazonInstantAccess::Authentication::DTA1_HMAC_SHA256}
            SignedHeaders=content-type;x-amz-date,
            Credential=KEYID/20110909,
            Signature=INCORRECT-SIGNATURE
        ).join(' '),
        'x-amz-date' => '20110909T233600Z',
        'content-type' => 'application/json'
    }
    expect {auth.verify_request *request}.to raise_error(AmazonInstantAccess::IncorrectSignatureError)
  end

  it 'should return without errors on correct signature (without resource path in URL)' do
    @headers = {
        'Authorization' => %W(
            #{AmazonInstantAccess::Authentication::DTA1_HMAC_SHA256}
            SignedHeaders=content-type;x-amz-date,
            Credential=KEYID/20110909,
            Signature=4d2f81ea2cf8d6963f8176a22eec4c65ae95c63502326a7c148686da7d50f47e
        ).join(' '),
        'x-amz-date' => '20110909T233600Z',
        'content-type' => 'application/json'
    }
    expect {auth.verify_request *request}.to_not raise_error(Exception)
  end

  it 'should return without errors on correct signature (with resource path in URL)' do
    @url = 'http://amazon.com/foobar'
    @headers = {
        'Authorization' => %W(
            #{AmazonInstantAccess::Authentication::DTA1_HMAC_SHA256}
            SignedHeaders=content-type;x-amz-date,
            Credential=KEYID/20110909,
            Signature=35ccb3e62bdfc93d4a58408162682a33f3d03a4ee9a9c0c9c3ef62b32b1a372f
        ).join(' '),
        'x-amz-date' => '20110909T233600Z',
        'content-type' => 'application/json'
    }
    expect {auth.verify_request *request}.to_not raise_error(Exception)
  end

  it 'should return without errors on correct signature (nil request body)' do
    @body = nil
    @headers = {
        'Authorization' => %W(
            #{AmazonInstantAccess::Authentication::DTA1_HMAC_SHA256}
            SignedHeaders=content-type;x-amz-date,
            Credential=KEYID/20110909,
            Signature=d3042ffc41e6456535558faa130655a1c957263467e78d4485e70884b49ea52b
        ).join(' '),
        'x-amz-date' => '20110909T233600Z',
        'content-type' => 'application/json'
    }
    expect {auth.verify_request *request}.to_not raise_error(Exception)
  end

  it 'should return without errors on receiving symbols instead of strings for credentials' do
    @credentials = {:KEYID => :SECRETKEY}
    @headers = {
        'Authorization' => %W(
            #{AmazonInstantAccess::Authentication::DTA1_HMAC_SHA256}
            SignedHeaders=content-type;x-amz-date,
            Credential=KEYID/20110909,
            Signature=4d2f81ea2cf8d6963f8176a22eec4c65ae95c63502326a7c148686da7d50f47e
        ).join(' '),
        'x-amz-date' => '20110909T233600Z',
        'content-type' => 'application/json'
    }
    expect {auth.verify_request *request}.to_not raise_error(Exception)
  end

end
