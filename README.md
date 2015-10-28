# ReCaptcha Secure Token

This library provides a PHP implementation of the ReCaptcha v2 
[Secure Token](https://developers.google.com/recaptcha/docs/secure_token) algorithm.

## Usage

You should add this library to your composer `require` section:

    "require": {
      "slushie/recaptcha-secure-token": "~1.0",
      /* ... */
    }

From within your PHP code, you can create an instance of the `ReCaptchaToken` class
and pass in your `site_key` and `site_secret` values:

    $config = ['site_key' => 'YOUR_SITE_KEY', 'site_secret' => 'YOUR_SITE_SECRET'];
    $recaptchaToken = new \ReCaptchaSecureToken\ReCaptchaToken($config);

To generate a *secure token* you must provide a unique `session_id`:

    $sessionId = uniqid('recaptcha');
    $secureToken = $recaptchaToken->secureToken($sessionId);

Finally, use this token value in your HTML output. For example:

    <div class="g-recaptcha" 
         data-sitekey="YOUR_SITE_KEY"
         data-stoken="<?php echo $secureToken ?>"></div>

### Timestamp

Being a time-based protocol, the timestamp must be accurate. If your system clock is not accurate (try `ntpdate`), you must pass an accurate timestamp (in ms) to `secureToken`. You can obtain one from an [NTP](https://github.com/bt51/ntp) server, e.g.:

    $socket = new Bt51\NPM\Socket('0.pool.ntp.org', 123);
    $ntp_client = new Bt51\NPM\Client($socket);
    $timestamp = $ntp_client->getTime()->getTimestamp() * 1000;

    $sessionId = uniqid('recaptcha');
    $secureToken = $recaptchaToken->secureToken($sessionId, $timestamp);

## Algorithm Implementation

The original ReCaptcha algorithm is undocumented, although 
[example source code](https://github.com/google/recaptcha-java) is
provided in Java. 

This implementation is based on the original Java implementation, as well
as some resources from around the web. Of important note are the follow:

  * <http://php.net/manual/en/mcrypt.ciphers.php>
  * <http://tools.ietf.org/html/rfc5652#section-6.3>
  * <http://www.networksorcery.com/enp/data/aes.htm>

For more implementation details, please see the source code.

## Security Considerations

There are multiple security flaws in the original implementation. Of particular 
note is the use of the `ECB` block mode, which is known to be insecure. A simple
example of this insecurity is available on 
[the Wikipedia article on Block cipher modes](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29).

This could theoretically lead to spammers acquiring your `site_secret`. 
No workaround is provided, **the secure token algorithm is inherently insecure**.

## License and Copyright

This code is Copyright 2015, Josh Leder. The original Java implementation is 
Copyright 2014, Google Inc. 

This code is provided under the Apache 2.0 license.
