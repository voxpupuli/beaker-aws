# Changelog

## [1.0.0](https://github.com/voxpupuli/beaker-aws/tree/1.0.0) (2021-07-22)

[Full Changelog](https://github.com/voxpupuli/beaker-aws/compare/0.9.0...1.0.0)

**Fixed bugs:**

- Fix 'InvalidInstanceIDNotFound' exception not being handled [\#27](https://github.com/voxpupuli/beaker-aws/pull/27) ([andersonvaf](https://github.com/andersonvaf))

**Merged pull requests:**

- Update GitHub actions + README.md [\#30](https://github.com/voxpupuli/beaker-aws/pull/30) ([bastelfreak](https://github.com/bastelfreak))
- Update fakefs requirement from ~\> 0.6, \<= 0.13.3 to ~\> 1.3, \<= 1.3.3 [\#29](https://github.com/voxpupuli/beaker-aws/pull/29) ([dependabot[bot]](https://github.com/apps/dependabot))
- Update rake requirement from ~\> 10.1 to ~\> 13.0 [\#28](https://github.com/voxpupuli/beaker-aws/pull/28) ([dependabot[bot]](https://github.com/apps/dependabot))
- Add GH Actions and Dependabot configs [\#25](https://github.com/voxpupuli/beaker-aws/pull/25) ([genebean](https://github.com/genebean))

## [0.9.0](https://github.com/voxpupuli/beaker-aws/tree/0.9.0) (2019-02-20)

[Full Changelog](https://github.com/voxpupuli/beaker-aws/compare/0.8.1...0.9.0)

**Merged pull requests:**

- \(PDK-1275\) fixes for the AWS hypervisor to account for netdev instances [\#24](https://github.com/voxpupuli/beaker-aws/pull/24) ([Thomas-Franklin](https://github.com/Thomas-Franklin))

## [0.8.1](https://github.com/puppetlabs/beaker-aws/tree/0.8.0) (2018-12-21)
[Full Changelog](https://github.com/puppetlabs/beaker-aws/compare/0.8.0...0.8.1)

**Merged pull requests:**

- \(maint\) Fix BKR-1546 for the case where subnet is nil

## [0.8.0](https://github.com/puppetlabs/beaker-aws/tree/0.8.0) (2018-12-12)
[Full Changelog](https://github.com/puppetlabs/beaker-aws/compare/0.7.0...0.8.0)

**Merged pull requests:**

- \(BKR-1546\) Added associate\_public\_ip\_address as host variable that is inserted into the AWS config if set

## [0.7.0](https://github.com/puppetlabs/beaker-aws/tree/0.7.0) (2018-08-27)
[Full Changelog](https://github.com/puppetlabs/beaker-aws/compare/0.6.0...0.7.0)

**Merged pull requests:**

- \(BKR-1522\) Add options to drop some of the provisioning
- \(BKR-1509\) Hypervisor usage instructions for Beaker 4.0

## [0.6.0](https://github.com/puppetlabs/beaker-aws/tree/0.6.0) (2018-07-16)
[Full Changelog](https://github.com/puppetlabs/beaker-aws/compare/0.5.0...0.6.0)

**Merged pull requests:**

- \(BKR-1481\) Rewrite beaker-aws to use shared .fog parsing [\#15](https://github.com/puppetlabs/beaker-aws/pull/15) ([Dakta](https://github.com/Dakta))
- Custom CIDRs for security group, none default VPC fixes [\#14](https://github.com/puppetlabs/beaker-aws/pull/14) ([ardeshireshghi](https://github.com/ardeshireshghi))
- \(MAINT\) Document Acceptance Test Setup [\#13](https://github.com/puppetlabs/beaker-aws/pull/13) ([Dakta](https://github.com/Dakta))

## [0.5.0](https://github.com/puppetlabs/beaker-aws/tree/0.5.0) (2018-06-13)
[Full Changelog](https://github.com/puppetlabs/beaker-aws/compare/0.4.0...0.5.0)

**Merged pull requests:**

- \(MAINT\) add changelog for 0.5.0 release [\#11](https://github.com/puppetlabs/beaker-aws/pull/11) ([kevpl](https://github.com/kevpl))
- \(BKR-1464\) Rewrite to use AWS SDK v3 [\#10](https://github.com/puppetlabs/beaker-aws/pull/10) ([rodjek](https://github.com/rodjek))
- \(MAINT\) Bump for new release [\#9](https://github.com/puppetlabs/beaker-aws/pull/9) ([cdenneen](https://github.com/cdenneen))
- \(BKR-1199\) Updated documentation for use\_fog\_credentials [\#8](https://github.com/puppetlabs/beaker-aws/pull/8) ([cdenneen](https://github.com/cdenneen))

## [0.4.0](https://github.com/puppetlabs/beaker-aws/tree/0.4.0) (2017-12-28)
[Full Changelog](https://github.com/puppetlabs/beaker-aws/compare/0.3.0...0.4.0)

**Merged pull requests:**

- \(bkr-1245\) beaker needs to set session id in aws configuration to enable mfa d bastion account use [\#7](https://github.com/puppetlabs/beaker-aws/pull/7) ([er0ck](https://github.com/er0ck))
- \(BKR-1244\) Set vmhostname to host.name since host\[:name\] is awlays nil [\#6](https://github.com/puppetlabs/beaker-aws/pull/6) ([samwoods1](https://github.com/samwoods1))
- \(BKR-1199\) adding condition to disable reading fog credentials [\#5](https://github.com/puppetlabs/beaker-aws/pull/5) ([cdenneen](https://github.com/cdenneen))

## [0.3.0](https://github.com/puppetlabs/beaker-aws/tree/0.3.0) (2017-08-02)
[Full Changelog](https://github.com/puppetlabs/beaker-aws/compare/0.2.0...0.3.0)

**Merged pull requests:**

- \(maint\) Open the orchestrator port on the master node [\#3](https://github.com/puppetlabs/beaker-aws/pull/3) ([jpartlow](https://github.com/jpartlow))

## [0.2.0](https://github.com/puppetlabs/beaker-aws/tree/0.2.0) (2017-08-01)
[Full Changelog](https://github.com/puppetlabs/beaker-aws/compare/0.1.0...0.2.0)

**Merged pull requests:**

- \(PE-21788\) Open port 8170 on ec2 masters [\#2](https://github.com/puppetlabs/beaker-aws/pull/2) ([jpartlow](https://github.com/jpartlow))

## [0.1.0](https://github.com/puppetlabs/beaker-aws/tree/0.1.0) (2017-07-21)
**Merged pull requests:**

- \(MAINT\) Use AWS's Ubuntu 16.04 AMI [\#1](https://github.com/puppetlabs/beaker-aws/pull/1) ([rishijavia](https://github.com/rishijavia))



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*


\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
