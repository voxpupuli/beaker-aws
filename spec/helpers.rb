# setup & require beaker's spec_helper.rb
beaker_gem_spec = Gem::Specification.find_by_name('beaker')
beaker_gem_dir = beaker_gem_spec.gem_dir
beaker_spec_path = File.join(beaker_gem_dir, 'spec')
$LOAD_PATH << beaker_spec_path
require File.join(beaker_spec_path, 'helpers.rb')

module TestFileHelpers

  def fog_file_contents
    { :default => { :aws_access_key_id => "IMANACCESSKEY",
                    :aws_secret_access_key => "supersekritkey",
                    :aws_session_token => 'somecrazylongsupersessiontoken!#%^^*(%$^&@$%#!!#$asd;fjapugfrejklvznb;jdgfjiadvij',
                    :aix_hypervisor_server => "aix_hypervisor.labs.net",
                    :aix_hypervisor_username => "aixer",
                    :aix_hypervisor_keyfile => "/Users/user/.ssh/id_rsa-acceptance",
                    :solaris_hypervisor_server => "solaris_hypervisor.labs.net",
                    :solaris_hypervisor_username => "harness",
                    :solaris_hypervisor_keyfile => "/Users/user/.ssh/id_rsa-old.private",
                    :solaris_hypervisor_vmpath => "rpoooool/zs",
                    :solaris_hypervisor_snappaths => ["rpoooool/USER/z0"],
                    :vsphere_server => "vsphere.labs.net",
                    :vsphere_username => "vsphere@labs.com",
                    :vsphere_password => "supersekritpassword"} }
  end

end

# Beaker HostHelpers
include HostHelpers
