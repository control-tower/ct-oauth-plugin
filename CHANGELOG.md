- Add support to per-app default redirect on email confirmation

# 1.8.13
- Fix issues on token generation

# 1.8.12
- Add support for JSON formatted responses on POST /auth/login and GET /auth/login endpoint

# 1.8.11
- Fix bug in rendering login template on auth failure

# 1.8.10
- Improve HTTP error codes on POST /auth/reset-password endpoint responses

# 1.8.9
- Add support for JSON formatted responses on POST /auth/reset-password endpoint
- Add support for JSON formatted responses on POST /auth/sign-up endpoint
- Add `disableEmailSending` configuration setting to disable email sending
- Fix issue where update to sparkpost integration lib prevented emails from being sent

# 1.8.8
- Add support for public user registration by setting `allowPublicRegistration` in the plugin config options

# 1.8.7
- Update dependencies to address security vulnerabilities
