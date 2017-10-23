Amazon Instant Access - Ruby SDK
================================

**Amazon Instant Access** (AIA) is a digital content fulfillment technology that allows purchases on the Amazon website
and delivery by third party vendors. This Ruby SDK provides the vendors a simple way to authenticate incoming requests
from Amazon. Please refer to our integration guide for [Subscriptions (SaaS)](https://s3-us-west-2.amazonaws.com/aia-docs/integration-guide-subscriptions.pdf) or [One-Time Purchasing](https://s3-us-west-2.amazonaws.com/aia-docs/integration-guide-one-time-purchases.pdf) to learn about the on-boarding procedure and the API specifications before using this SDK.

Installation
------------
Run the following set of commands to install the latest version from
[GitHub](https://github.com/amzn/amazon-instant-access-sdk-ruby):

```bash
~$ git clone https://github.com/amzn/amazon-instant-access-sdk-ruby.git
~$ cd amazon-instant-access-sdk-ruby
~$ gem build amazon-instant-access.gemspec
~$ gem install amazon-instant-access-*.gem
```

Note that `sudo` may be required depending on the environment.


Getting Started
---------------

This instruction assumes that the vendor has already started implementing the web service for handling HTTP requests from Amazon Instant Access, and is already familiar with the integration API. The SDK is for authenticating **account linking** and **fulfillment (service)** requests from Amazon.

Here is a simple example of Ruby on Rails controller a vendor might start out with:

```ruby
class VendorFulfillmentController < ApplicationController

  def create
    operation = params['operation']
    if operation == 'Purchase'
      # Vendor logic
    elsif operation == 'Revoke'
      # Vendor logic
    elsif operation == 'SubscriptionActivate'
      # Vendor logic
    elsif operation == 'SubscriptionDeactivate'
      # Vendor logic
    end
    render json: {response: 'OK'}, status: :ok
  end

end
```

Use the SDK to enable authentication in the controller:

```ruby
require 'amazon-instant-access'

class VendorFulfillmentController < ApplicationController

  def create
    credentials = {'public_key' => 'secret_key'}
    auth = AmazonInstantAccess::Authentication.new(credentials)
    auth.verify_request(
      request.method,
      request.url,
      request.raw_post,
      request.headers
    )

    operation = params['operation']
    if operation == 'Purchase'
      # Vendor logic
    elsif operation == 'Revoke'
      # Vendor logic
    elsif operation == 'SubscriptionActivate'
      # Vendor logic
    elsif operation == 'SubscriptionDeactivate'
      # Vendor logic
    end
    render json: {response: 'OK'}, status: :ok
  end

end
```
The signature of the method `AmazonInstantAccess::Authentication.verify_request` is as follows:

```ruby
auth.verify_request(
  request.method,   # [String] HTTP method of the request (e.g. 'POST')
  request.url,      # [String] full URL of the request (e.g. 'https://vendor.com/api/fulfillment')
  request.raw_post, # [String] raw body (payload) of the request
  request.headers   # [Object] an object or hash representing the headers (must allow case-insensitive, string key based access)
)
```

Note that the example above is specific to Ruby on Rails, and the method arguments may have to be modified depending on the
web framework in use by the vendor. The credentials should not be hardcoded but obtained from a secure, external source (e.g. file with correct permissions).

Logging
-------

Once set up, the `AmazonInstantAccess::Authentication` instance will automatically compute and verify the request
signature. It will also log detailed messages to `./amazon_instant_access_auth.log`. The location of the log file and
the logging behavior can be customized by passing in a new logger instance into the initializer:

```ruby
require 'logger'
require 'amazon-instant-access'

class VendorFulfillmentController < ApplicationController

  def create
    credentials = {'public_key' => 'secret_key'}
    
    # Create a custom logger
    custom_logger = Logger.new('vendor_custom_log.log')

    # Pass in the logger into the initializer to override the default one
    auth = AmazonInstantAccess::Authentication.new(credentials, custom_logger)
    auth.verify_request(
      request.method,
      request.url,
      request.raw_post,
      request.headers
    )

    operation = params['operation']
    if operation == 'Purchase'
      # Vendor logic
    elsif operation == 'Revoke'
      # Vendor logic
    elsif operation == 'SubscriptionActivate'
      # Vendor logic
    elsif operation == 'SubscriptionDeactivate'
      # Vendor logic
    end
    render json: {response: 'OK'}, status: :ok
  end

end
```

Error Handling
--------------

If the authentication fails for any reason, the `AmazonInstanceAccess::Authentication` instance will raise exceptions
specific to the issue. These should be caught and handled appropriately by the vendors. Here is an example showing all
exceptions that are designed to be thrown by the SDK:

```ruby
require 'amazon-instant-access'

class VendorFulfillmentController < ApplicationController

  def create
    credentials = {'public_key' => 'secret_key'}
    auth = AmazonInstantAccess::Authentication.new(credentials)

    # Handle authentication failures using a try-catch
    request_successfully_verified = false
    begin
        auth.verify_request(
          request.method,
          request.url,
          request.raw_post,
          request.headers
        )
    rescue AmazonInstantAccess::MissingHeaderError => error
      puts "The request is missing an important header: #{error.message}"
    rescue AmazonInstantAccess::MalformedAuthHeaderError => error
      puts "The 'Authorization' header is malformed: #{error.message}"
    rescue AmazonInstantAccess::ExpiredRequestError
      puts 'The request is now expired'
    rescue AmazonInstantAccess::IncorrectSignatureError
      puts 'The request signature does not match the expected one'
    rescue AmazonInstantAccess::UnknownPublicKeyError
      puts 'The request contains an unknown public key'
    rescue AmazonInstantAccess::UnsupportedAlgorithmError
      puts 'The request had an invalid hash algorithm (only HMAC SHA256 supported currently)'
    else
      request_successfully_verified = true
    end

    if request_successfully_verified
        operation = params['operation']
        if operation == 'Purchase'
          # Vendor logic
        elsif operation == 'Revoke'
          # Vendor logic
        elsif operation == 'SubscriptionActivate'
          # Vendor logic
        elsif operation == 'SubscriptionDeactivate'
          # Vendor logic
        end
        render json: {response: 'OK'}, status: :ok
    else
        render json: {response: 'FAIL_OTHER'}, status: :bad_request
    end
  end

end
```

Alternatively, the parent exception `AmazonInstantAccess::AuthenticationError` can be caught to reduce verbosity:

```ruby
require 'amazon-instant-access'

class VendorFulfillmentController < ApplicationController

  def create
    credentials = {'public_key' => 'secret_key'}
    auth = AmazonInstantAccess::Authentication.new(credentials)

    request_successfully_verified = false
    begin
        auth.verify_request(
          request.method,
          request.url,
          request.raw_post,
          request.headers
        )
    rescue AmazonInstantAccess::AuthenticationError => error
      puts "Authentication failed: #{error.message}"
    else
      request_successfully_verified = true
    end

    if request_successfully_verified
        operation = params['operation']
        if operation == 'Purchase'
          # Vendor logic
        elsif operation == 'Revoke'
          # Vendor logic
        elsif operation == 'SubscriptionActivate'
          # Vendor logic
        elsif operation == 'SubscriptionDeactivate'
          # Vendor logic
        end
        render json: {response: 'OK'}, status: :ok
    else
        render json: {response: 'FAIL_OTHER'}, status: :bad_request
    end
  end

end
```

Credentials
-----------

If multiple credentials are required, simply add them into the input credentials on initialization:
```ruby
credentials = {
  'public_key1' => 'secret_key1',
  'public_key2' => 'secret_key2',
  'public_key3' => 'secret_key3',
  ...
}
auth = AmazonInstantAccess::Authentication.new(credentials)

```


Contact
-------

Send an email to d3-support@amazon.com for technical support and any other enquiries on the SDK. Please include your
company name in the subject line to make tracking easier.
