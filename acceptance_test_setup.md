Notes on testing `beaker-aws` if your AWS configuration requires MFA or IAM Roles.

# MAF and IAM Role

If the credentials you use to access EC2 require MFA (Milti-Factor Authentication), the current workflow is to manually fetch a session token then set it in `.fog` under `aws_session_token`:

1. Install AWS CLI tools.
2. Configure your shared credentials in `~/.aws`
3. Get a temporary role session
    ~~~console
    $ aws sts assume-role --role-arn <ROLE_ARN_STRING> --role-session-name "<SESSION_NAME>" --serial-number <MFA_ARN_STRING> --token-code <MFA_TOKEN>
    {
        "Credentials": {
            "AccessKeyId": "accesskeyid",
            "SecretAccessKey": "secretaccesskey",
            "SessionToken": "somesuperlongsessiontoken",
            "Expiration": "2018-06-25T19:54:04Z"
        },
        "AssumedRoleUser": {
            "AssumedRoleId": "<SESSION_ROLE_ID>",
            "Arn": "<NAMED_ROLE_SESSION>"
        }
    }
    ~~~
4. Extract `AccessKeyId`, `SecretAccessKey`, and `SessionToken` and put them in your `.fog` file as `aws_access_key_id`, `aws_secret_access_key`, and `aws_session_token`. By default this session will be valid for one hour. See `aws sts assume-role help` to extend the session lifetime.
5. You can now run beaker (or `beaker-aws` acceptance tests) on AWS:
    ~~~console
    $ bundle exec rake test:acceptance
    ~~~
    As always, be sure you have configured a passwordless SSH key. These tests look for `~/.ssh/id_rsa` as the default to provision SUTs with.

# Shared Credentials

In theory, there should eventually be support for roles from shared credentials in `~/.aws/` from the Ruby AWS SDK directly, but [that functionality is on the backlog](https://github.com/aws/aws-sdk-ruby/issues/1256). Regardless, that doesn't seem like it would necessarily work with MFA.

Support for IAM Roles and MFA are not formally planned for beaker-aws.
