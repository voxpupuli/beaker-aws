require 'beaker/hypervisor/aws_sdk'

# This parent class is used because beaker accepts 'ec2' as hypervisor argument for AWS hosts
# Beaker then will convert 'ec2' to 'Ec2' therefore the classname
# Naming it 'Ec2' class will also prevent conflicts with AWS's 'EC2' fs class

module Beaker
  class Ec2 < AwsSdk
  end
end
