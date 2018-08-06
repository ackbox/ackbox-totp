# TOTP authenticator written in Kotlin

This small lib is highly inspired by [GoogleAuth](https://github.com/wstrange/GoogleAuth). It implements the Time-based One-time Password (TOTP) algorithm specified in [RFC 6238](https://tools.ietf.org/html/rfc6238). It introduces additional abstractions that are intended to provided extension points for other implementations/providers of TOTP.

## Using the library

If you're using Maven, simply add the following dependency to your `POM.xml` file:

```xml
<dependency>
  <groupId>com.ackbox</groupId>
  <artifactId>ackbox-totp</artifactId>
  <version>1.0.1</version>
</dependency>
```

Or if you prefer Gradle, include the following declaration to your `build.gradle` file:

```
compile 'com.ackbox:ackbox-totp:1.0.1'
```

## Usage

### Registering with pre-existent TOTP authenticator applications
 
You can use pre-existent TOTP authentication applications (e.g. Google Authenticator) or implement your own TOTP provider integration. In order to use a pre-existent provider, simply use `TOTPProviders` class to retrieve an instance of `TOTPAuthenticator`.

```kotlin
val authenticator = TOTPProviders.googleAuthenticator()
val credentials = authenticator.createCredentials()

val secretKey = credentials.secretKey // You might want to store this value for a given user
val verificationCode = credentials.verificationCode // You might want to store this value for a given user
val scratchCodes = credentials.scratchCodes // You might want to store this value for a given user
```

With a new instance of `TOTPAuthenticator`, you can register your application with a TOTP authenticator app of your choice using QR code:

```kotlin
val applicationName = "MyAppName"
val userAccountName = "user@myapp.com"
val urlToQRCode = authenticator.createQRCode(applicationName, userAccountName, credentials.secretKey)
```

### Authentication using TOTP applications

Now that your application is registered with a TOTP authenticator application, you can use generated TOTP codes to authenticate users:

```kotlin
val userCodeFromTOTPApplication = 123456
val userSecretKey = MyUserRepository().retrieveUserSecretKey(userAccountName) 
val isAuthorized = authenticator.authorize(userSecretKey, userCodeFromTOTPApplication)
```

### Scratch codes

By default 5 scratch codes are generated together with a new shared secret. Scratch codes are meant to be a safety net in case a user loses access to their token device. Scratch nodes are not a functionality required by the TOTP standard and it is up to the developer to decide whether they should be used in his application.

## Supported TOTP providers

### Google Authenticator

The library comes with TOTP implementation compatible with [Google Authenticator App](https://support.google.com/accounts/answer/1066447?hl=en). The current implementation provides a set of configurable settings:
 
```kotlin
val configuration = GoogleAuthenticatorConfig(
    timeStepSize = Duration.ofSeconds(30), // Time step size as specified by RFC 6238.
    windowSize = 3, // Value representing the number of windows of size timeStepSize that are checked during the validation process, to account for differences between the server and the client clocks.
    codeDigits = 6, // Number of digits in the generated code.
    keyModulus = Math.pow(10.0, codeDigits.toDouble()).toLong() // Key modulus as specified by RFC 6238. 
)
val authenticator = TOTPProviders.googleAuthenticator(configuration)
```