require 'spec_helper'

module Beaker
  describe AwsSdk do
    let( :options ) { make_opts.merge({ 'logger' => double().as_null_object, 'timestamp' => Time.now }) }
    let(:aws) {
      # Mock out the call to load_fog_credentials
      allow_any_instance_of( Beaker::AwsSdk ).
        to receive(:load_fog_credentials).
        and_return(Aws::Credentials.new(
          fog_file_contents[:default][:aws_access_key_id],
          fog_file_contents[:default][:aws_secret_access_key],
          fog_file_contents[:default][:aws_session_token],
        ))


      # This is needed because the EC2 api looks up a local endpoints.json file
      FakeFS.deactivate!
      aws = Beaker::AwsSdk.new(@hosts, options)
      aws_partitions_dir = Gem::Specification.find_by_name('aws-partitions').gem_dir
      FakeFS.activate!
      allow(File).to receive(:exist?).with(File.join(aws_partitions_dir, 'partitions.json'))
      FakeFS::FileSystem.clone(File.join(aws_partitions_dir, 'partitions.json'))

      aws
    }
    let(:amispec) {{
      "centos-5-x86-64-west" => {
        :image => {:pe => "ami-sekrit1"},
        :region => "us-west-2",
      },
      "centos-6-x86-64-west" => {
        :image => {:pe => "ami-sekrit2"},
        :region => "us-west-2",
      },
      "centos-7-x86-64-west" => {
        :image => {:pe => "ami-sekrit3"},
        :region => "us-west-2",
      },
      "ubuntu-12.04-amd64-west" => {
        :image => {:pe => "ami-sekrit4"},
        :region => "us-west-2"
      },
    }}

    before :each do
      @hosts = make_hosts({:snapshot => :pe}, 6)
      @hosts[0][:platform] = "centos-5-x86-64-west"
      @hosts[1][:platform] = "centos-6-x86-64-west"
      @hosts[2][:platform] = "centos-7-x86-64-west"
      @hosts[3][:platform] = "ubuntu-12.04-amd64-west"
      @hosts[3][:user] = "ubuntu"
      @hosts[4][:platform] = 'f5-host'
      @hosts[4][:user] = 'notroot'
      @hosts[5][:platform] = 'netscaler-host'

      ENV['AWS_ACCESS_KEY'] = nil
      ENV['AWS_SECRET_ACCESS_KEY'] = nil
    end

    context 'loading credentials' do

      it 'from .fog file' do
        creds = aws.load_fog_credentials
        expect(creds).to have_attributes(
          :access_key_id => 'IMANACCESSKEY',
          :secret_access_key => 'supersekritkey',
          :session_token =>'somecrazylongsupersessiontoken!#%^^*(%$^&@$%#!!#$asd;fjapugfrejklvznb;jdgfjiadvij',
        )
      end


      it 'from environment variables' do
        ENV['AWS_ACCESS_KEY_ID'] = "IMANACCESSKEY"
        ENV['AWS_SECRET_ACCESS_KEY'] = "supersekritkey"

        creds = aws.load_env_credentials
        expect(creds).to have_attributes(
          :access_key_id => "IMANACCESSKEY",
          :secret_access_key => "supersekritkey",
          :session_token => nil,
        )
      end

      it 'from environment variables with session_token' do
        ENV['AWS_ACCESS_KEY_ID'] = "IMANACCESSKEY"
        ENV['AWS_SECRET_ACCESS_KEY'] = "supersekritkey"
        ENV['AWS_SESSION_TOKEN'] = 'somesuperlongsessiontokenspecialcharsblah!#%$#@$^!@qewpofudjsvjm'

        creds = aws.load_env_credentials
        expect(creds).to have_attributes(
          :access_key_id => "IMANACCESSKEY",
          :secret_access_key => "supersekritkey",
          :session_token => 'somesuperlongsessiontokenspecialcharsblah!#%$#@$^!@qewpofudjsvjm',
        )
      end

    end

    context 'dont read fog credentials' do
      let(:options) { make_opts.merge({ 'use_fog_credentials' => false }) }

      before(:each) do
        ENV.delete('AWS_ACCESS_KEY_ID')
      end

      it 'not using fog' do
        creds = aws.load_env_credentials
        expect(creds).to have_attributes(
          :access_key_id => nil,
          :secret_access_key => nil,
        )
        expect(options[:use_fog_credentials]).to eq(false)
      end
    end

    describe '#provision' do
      before :each do
        expect(aws).to receive(:launch_all_nodes)
        expect(aws).to receive(:add_tags)
        expect(aws).to receive(:populate_dns)
        expect(aws).to receive(:enable_root_on_hosts)
        expect(aws).to receive(:set_hostnames)
        expect(aws).to receive(:configure_hosts)
      end

      it 'should step through provisioning' do
        allow( aws ).to receive( :wait_for_status_netdev )
        aws.provision
      end

      it 'should return nil' do
        allow( aws ).to receive( :wait_for_status_netdev )
        expect(aws.provision).to be_nil
      end
    end

    describe '#kill_instances' do
      def mock_instance(id, state)
        instance_double(
          Aws::EC2::Types::Instance,
          :state       => instance_double(Aws::EC2::Types::InstanceState, :name => state),
          :instance_id => id,
        )
      end

      let(:ec2_instance) { mock_instance('ec2', 'running') }
      let(:vpc_instance) { mock_instance('vpc', 'running') }
      let(:nil_instance) { nil }
      let(:unreal_instance) { mock_instance('unreal', 'terminated') }

      subject(:kill_instances) { aws.kill_instances(instance_set) }
      let(:mock_client) { instance_double(Aws::EC2::Client, :terminate_instances => nil) }

      before(:each) do
        allow(aws).to receive(:client).and_return(mock_client)
        allow(aws).to receive(:instance_by_id).with('ec2').and_return(ec2_instance)
        allow(aws).to receive(:instance_by_id).with('vpc').and_return(vpc_instance)
        allow(aws).to receive(:instance_by_id).with('nil').and_return(nil_instance)
        allow(aws).to receive(:instance_by_id).with('unreal').and_return(unreal_instance)
      end

      it 'should return nil' do
        instance_set = [ec2_instance, vpc_instance, nil_instance, unreal_instance]
        expect(aws.kill_instances(instance_set)).to be_nil
      end

      it 'cleanly handles an empty instance list' do
        instance_set = []
        expect(aws.kill_instances(instance_set)).to be_nil
      end

      context 'in general use' do
        let( :instance_set ) { [ec2_instance, nil_instance, vpc_instance] }

        it 'terminates each running instance' do
          expect(mock_client).to receive(:terminate_instances).with(
            :instance_ids => [ec2_instance.instance_id, vpc_instance.instance_id],
          )

          expect(kill_instances).to be_nil
        end

        it 'verifies instances exist in AWS' do
          instance_set.compact.each do |instance|
            expect(aws).to receive(:instance_by_id).with(instance.instance_id)
          end

          expect(kill_instances).to be_nil
        end
      end

      context 'for a single running instance' do
        let( :instance_set ) { [ec2_instance] }

        it 'terminates the running instance' do
          expect(mock_client).to receive(:terminate_instances).with(
            :instance_ids => [ec2_instance.instance_id],
          )

          expect(kill_instances).to be_nil
        end

        it 'verifies instance exists in AWS' do
          instance_set.each do |instance|
            expected_state = instance_double(Aws::EC2::Types::InstanceState, :name => 'running')
            expect(instance).to receive(:state).and_return(expected_state)
          end

          expect(mock_client).to receive(:terminate_instances).with(
            :instance_ids => [ec2_instance.instance_id],
          )

          expect(kill_instances).to be_nil
        end
      end

      context 'when an instance does not exist' do
        let( :instance_set ) { [unreal_instance] }

        it 'does not call terminate' do
          expect(mock_client).not_to receive(:terminate_instances)
          expect(kill_instances).to be_nil
        end

        it 'verifies instance does not exist' do
          instance_set.each do |instance|
            expected_state = instance_double(Aws::EC2::Types::InstanceState, :name => 'terminated')
            expect(instance).to receive(:state).and_return(expected_state)
          end

          expect(mock_client).not_to receive(:terminate_instances)
          expect(kill_instances).to be_nil
        end
      end

      context 'when an instance is nil' do
        let(:instance_set) { [nil_instance] }

        it 'does not call terminate' do
          expect(mock_client).not_to receive(:terminate_instances)

          expect(kill_instances).to be_nil
        end
      end
    end

    describe '#cleanup' do
      subject(:cleanup) { aws.cleanup }
      let(:ec2_instance) do
        instance_double(Aws::EC2::Types::Instance,
          :instance_id => 'id',
          :state       => instance_double(Aws::EC2::Types::InstanceState, :name => 'running'),
        )
      end

      context 'with a list of hosts' do
        before :each do
          @hosts.each { |host| host['instance'] = ec2_instance }
          expect(aws).to receive(:delete_key_pair_all_regions)
        end

        it 'kills instances' do
          expect(aws).to receive(:kill_instances).once
          expect(cleanup).to be_nil
        end
      end

      context 'with an empty host list' do
        before :each do
          @hosts = []
          expect(aws).to receive( :delete_key_pair_all_regions )
        end

        it 'kills instances' do
          expect(aws).to receive(:kill_instances).once
          expect(cleanup).to be_nil
        end
      end
    end

    describe '#log_instances', :wip do
    end

    describe '#instance_by_id', :wip do
    end

    describe '#instances', :wip do
    end

    describe '#vpc_by_id', :wip do
    end

    describe '#vpcs', :wip do
    end

    describe '#security_group_by_id', :wip do
    end

    describe '#security_groups', :wip do
    end

    describe '#kill_zombies' do
      it 'calls delete_key_pair_all_regions' do
        allow(aws).to receive(:regions).and_return([])

        expect(aws).to receive(:kill_instances).once
        expect(aws).to receive(:delete_key_pair_all_regions).once

        aws.kill_zombies
      end
    end

    describe '#kill_zombie_volumes', :wip do
    end

    describe '#create_instance', :wip do
    end

    describe '#launch_nodes_on_some_subnet', :wip do
    end

    describe '#launch_all_nodes', :wip do
    end

    describe '#wait_for_status' do
      let( :aws_instance ) { instance_double(Aws::EC2::Types::Instance, :instance_id => "ec2") }
      let( :instance_set ) { [{:instance => aws_instance, :host => instance_double(Beaker::Host, :name => 'test')}] }
      subject(:wait_for_status) { aws.wait_for_status(:running, instance_set) }

      def mock_instance(state, other = {})
        r = instance_double(
          Aws::EC2::Types::Instance,
          :instance_id => 'ec2',
          :state       => instance_double(Aws::EC2::Types::InstanceState, :name => state),
        )

        other.each do |k, v|
          allow(r).to receive(:[]).with(k).and_return(v)
        end

        r
      end

      context 'single instance' do
        it 'behaves correctly in typical case' do
          allow(aws).to receive(:instance_by_id).with('ec2').and_return(mock_instance(:waiting), mock_instance(:waiting), mock_instance(:running))
          expect(aws).to receive(:backoff_sleep).exactly(3).times
          expect(wait_for_status).to eq(instance_set)
        end

        it 'executes block correctly instead of status if given one' do
          barn_value = 'did you grow up in a barn?'
          expect(aws).to receive(:instance_by_id).and_return(mock_instance(:running, :barn => barn_value))
          expect(aws).to receive(:backoff_sleep).exactly(1).times
          aws.wait_for_status(:running, instance_set) do |instance|
            expect( instance[:barn] ).to be === barn_value
            true
          end
        end
      end

      context 'with multiple instances' do
        let(:instance_set) do
          [
            { :instance => aws_instance, :host => instance_double(Beaker::Host, :name => 'test1') },
            { :instance => aws_instance, :host => instance_double(Beaker::Host, :name => 'test2') },
          ]
        end

        it 'returns the instance set passed to it' do
          allow(aws).to receive(:instance_by_id).and_return(
            mock_instance(:waiting),
            mock_instance(:waiting),
            mock_instance(:running),
            mock_instance(:waiting),
            mock_instance(:waiting),
            mock_instance(:running)
          )
          allow(aws).to receive(:backoff_sleep).exactly(6).times
          expect(wait_for_status).to eq(instance_set)
        end

        it 'calls backoff_sleep once per instance.status call' do
          allow(aws).to receive(:instance_by_id).and_return(
            mock_instance(:waiting),
            mock_instance(:waiting),
            mock_instance(:running),
            mock_instance(:waiting),
            mock_instance(:waiting),
            mock_instance(:running),
          )
          expect(aws).to receive(:backoff_sleep).exactly(6).times
          expect(wait_for_status).to eq(instance_set)
        end

        it 'executes block correctly instead of status if given one' do
          barn_value = 'did you grow up in a barn?'
          not_barn_value = 'notabarn'
          allow(aws_instance).to receive( :[] ).with( :barn ).and_return(not_barn_value, barn_value, not_barn_value, barn_value)
          allow(aws).to receive(:instance_by_id).and_return(
            mock_instance(:waiting, :barn => not_barn_value),
            mock_instance(:waiting, :barn => barn_value),
            mock_instance(:waiting, :barn => not_barn_value),
            mock_instance(:waiting, :barn => barn_value),
          )
          expect(aws).to receive(:backoff_sleep).exactly(4).times
          aws.wait_for_status(:running, instance_set) do |instance|
            instance[:barn] == barn_value
          end
        end
      end

      context 'after 10 tries' do
        it 'raises RuntimeError' do
          expect(aws).to receive(:instance_by_id).and_return(mock_instance(:waiting)).exactly(10).times
          expect(aws).to receive(:backoff_sleep).exactly(9).times
          expect { wait_for_status }.to raise_error('Instance never reached state running')
        end

        it 'still raises RuntimeError if given a block' do
          expect(aws).to receive(:instance_by_id).and_return(mock_instance(:waiting)).exactly(10).times
          expect(aws).to receive(:backoff_sleep).exactly(9).times
          expect { wait_for_status { false } }.to raise_error('Instance never reached state running')
        end
      end
    end

    describe '#add_tags' do
      let(:aws_instance) { instance_double(Aws::EC2::Types::Instance, :instance_id => 'id-123') }
      let(:mock_client) { instance_double(Aws::EC2::Client) }

      subject(:add_tags) { aws.add_tags }

      before(:each) do
        allow(aws).to receive(:client).and_return(mock_client)
        allow(mock_client).to receive(:create_tags)
      end

      it 'returns nil' do
        @hosts.each {|host| host['instance'] = aws_instance}
        expect(add_tags).to be_nil
      end

      context 'with multiple hosts' do
        before :each do
          @hosts.each_with_index do |host, i|
            host['instance'] = instance_double(Aws::EC2::Types::Instance, :instance_id => "id-#{i}")
          end
        end

        it 'handles host_tags hash on host object' do
          # set :host_tags on first host
          @hosts[0][:host_tags] = {'test_tag' => 'test_value'}

          expect(mock_client).to receive(:create_tags).with(
            :resources => [@hosts[0]['instance'].instance_id],
            :tags      => include(
              {
                :key   => 'test_tag',
                :value => 'test_value',
              },
            ),
          ).once

          expect(add_tags).to be_nil
        end

        it 'adds tag for jenkins_build_url' do
          aws.instance_eval('@options[:jenkins_build_url] = "my_build_url"')

          expect(mock_client).to receive(:create_tags).with(
            :resources => anything,
            :tags      => include(
              {
                :key   => 'jenkins_build_url',
                :value => 'my_build_url',
              },
            ),
          ).at_least(:once)

          expect(add_tags).to be_nil
        end

        it 'adds tag for Name' do
          expect(mock_client).to receive(:create_tags).with(
            :resources => anything,
            :tags      => include(
              {
                :key   => 'Name',
                :value => a_string_matching(/vm/),
              },
            ),
          ).at_least(:once)

          expect(add_tags).to be_nil
        end

        it 'adds tag for department' do
          aws.instance_eval('@options[:department] = "my_department"')

          expect(mock_client).to receive(:create_tags).with(
            :resources => anything,
            :tags      => include(
              {
                :key   => 'department',
                :value => 'my_department',
              },
            ),
          ).at_least(:once)

          expect(add_tags).to be_nil
        end

        it 'adds tag for project' do
          aws.instance_eval('@options[:project] = "my_project"')

          expect(mock_client).to receive(:create_tags).with(
            :resources => anything,
            :tags      => include(
              {
                :key   => 'project',
                :value => 'my_project',
              },
            ),
          ).at_least(:once)

          expect(add_tags).to be_nil
        end

        it 'adds tag for created_by' do
          aws.instance_eval('@options[:created_by] = "my_created_by"')

          expect(mock_client).to receive(:create_tags).with(
            :resources => anything,
            :tags      => include(
              {
                :key   => 'created_by',
                :value => 'my_created_by',
              },
            ),
          ).at_least(:once)

          expect(add_tags).to be_nil
        end
      end
    end

    describe '#populate_dns' do
      let( :vpc_instance ) do
        instance_double(Aws::EC2::Types::Instance, public_ip_address: nil, private_ip_address: "vpc_private_ip", public_dns_name: "vpc_dns_name")
      end
      let( :ec2_instance ) do
        instance_double(Aws::EC2::Types::Instance, public_ip_address: "ec2_public_ip", private_ip_address: "ec2_private_ip", public_dns_name: "ec2_dns_name")
      end
      subject(:populate_dns) { aws.populate_dns }
      subject(:hosts) { aws.instance_variable_get(:@hosts) }

      context 'on a public EC2 instance' do
        before :each do
          @hosts.each { |host| host['instance'] = ec2_instance }

          populate_dns
        end

        it 'sets host ip to instance.public_ip_address' do
          hosts.each do |host|
            expect(host['ip']).to eql(ec2_instance.public_ip_address)
          end
        end

        it 'sets host private_ip to instance.private_ip_address' do
          hosts.each do |host|
            expect(host['private_ip']).to eql(ec2_instance.private_ip_address)
          end
        end

        it 'sets host dns_name to instance.public_dns_name' do
          hosts.each do |host|
            expect(host['dns_name']).to eql(ec2_instance.public_dns_name)
          end
        end
      end

      context 'on a VPC based instance' do
        before :each do
          @hosts.each { |host| host['instance'] = vpc_instance }

          populate_dns
        end

        it 'sets host ip to instance.private_ip_address' do
          hosts.each do |host|
            expect(host['ip']).to eql(vpc_instance.private_ip_address)
          end
        end

        it 'sets host private_ip to instance.private_ip_address' do
          hosts.each do |host|
            expect(host['private_ip']).to eql(vpc_instance.private_ip_address)
          end
        end

        it 'sets host dns_name to instance.public_dns_name' do
          hosts.each do |host|
            expect(host['dns_name']).to eql(vpc_instance.public_dns_name)
          end
        end
      end
    end

    describe '#etc_hosts_entry' do
      let( :host ) { @hosts[0] }
      let( :interface ) { :ip }
      subject(:etc_hosts_entry) { aws.etc_hosts_entry(host, interface) }

      it 'returns a predictable host entry' do
        expect(aws).to receive(:get_domain_name).and_return('lan')
        expect(etc_hosts_entry).to eq("ip.address.for.vm1\tvm1 vm1.lan vm1.box.tld\n")
      end

      context 'when :private_ip is requested' do
        let( :interface ) { :private_ip }
        it 'returns host entry for the private_ip' do
          host = @hosts[0]
          expect(aws).to receive(:get_domain_name).and_return('lan')
          expect(etc_hosts_entry).to eq("private.ip.for.vm1\tvm1 vm1.lan vm1.box.tld\n")
        end
      end
    end

    describe '#configure_hosts' do
      subject(:configure_hosts) { aws.configure_hosts }

      it { is_expected.to be_nil }

      context 'calls #set_etc_hosts' do
        it 'for each host (except the f5 ones)' do
          non_netdev_hosts = @hosts.select{ |h| !(h['platform'] =~ /f5|netscaler/) }
          expect(aws).to receive(:set_etc_hosts).exactly(non_netdev_hosts.size).times
          expect(configure_hosts).to be_nil
        end

        it 'with predictable host entries' do
          @hosts = [@hosts[0], @hosts[1]]
          entries = "127.0.0.1\tlocalhost localhost.localdomain\n"\
                    "private.ip.for.vm1\tvm1 vm1.lan vm1.box.tld\n"\
                    "ip.address.for.vm2\tvm2 vm2.lan vm2.box.tld\n"
          allow(aws).to receive(:get_domain_name).and_return('lan')
          expect(aws).to receive(:set_etc_hosts).with(@hosts[0], entries)
          expect(aws).to receive(:set_etc_hosts).with(@hosts[1], anything)
          expect(configure_hosts).to be_nil
        end
      end
    end

    describe '#enable_root_on_hosts' do
      context 'enabling root shall be called once for the ubuntu machine' do
        it "should enable root once" do
          allow(aws).to receive(:enable_root_netscaler)
          expect( aws ).to receive(:copy_ssh_to_root).with( @hosts[3], options ).once()
          expect( aws ).to receive(:enable_root_login).with( @hosts[3], options).once()
          aws.enable_root_on_hosts();
        end
      end

      it 'enables root once on the f5 host through its code path' do
        allow(aws).to receive(:enable_root_netscaler)
        expect( aws ).to receive(:enable_root_f5).with( @hosts[4] ).once()
        aws.enable_root_on_hosts()
      end
    end

    describe '#enable_root_f5' do
      let( :f5_host ) { @hosts[4] }
      subject(:enable_root_f5) { aws.enable_root_f5(f5_host) }

      it 'creates a password on the host' do
        result_mock = Beaker::Result.new(f5_host, '')
        result_mock.exit_code = 0
        allow( f5_host ).to receive( :exec ).and_return(result_mock)
        allow( aws ).to receive( :backoff_sleep )
        sha_mock = Object.new
        allow( Digest::SHA256 ).to receive( :new ).and_return(sha_mock)
        expect( sha_mock ).to receive( :hexdigest ).once()
        enable_root_f5
      end

      it 'tries 10x before failing correctly' do
        result_mock = Beaker::Result.new(f5_host, '')
        result_mock.exit_code = 2
        allow( f5_host ).to receive( :exec ).and_return(result_mock)
        expect( aws ).to receive( :backoff_sleep ).exactly(9).times
        expect{ enable_root_f5 }.to raise_error( RuntimeError, /unable/ )
      end
    end

    describe '#enable_root_netscaler' do
      let(:ns_host) { @hosts[5] }
      subject(:enable_root_netscaler) { aws.enable_root_netscaler(ns_host) }

      it 'set password to instance id of the host' do
        ns_host["instance"] = instance_double(Aws::EC2::Types::Instance, :instance_id => 'i-842018')
        enable_root_netscaler
        expect(ns_host['ssh'][:password]).to eql("i-842018")
      end
    end

    describe '#set_hostnames' do
      subject(:set_hostnames) { aws.set_hostnames }
      it 'returns @hosts' do
        expect(set_hostnames).to eq(@hosts)
      end

      context 'for each host' do
        it 'calls exec' do
          @hosts.each do |host|
            expect(host).to receive(:exec).once unless host['platform'] =~ /netscaler/
          end
          expect(set_hostnames).to eq(@hosts)
        end

        it 'passes a Command instance to exec' do
          @hosts.each do |host|
            expect(host).to receive(:exec).with( instance_of(Beaker::Command) ).once unless host['platform'] =~ /netscaler/
          end
          expect(set_hostnames).to eq(@hosts)
        end

        it 'sets the the vmhostname to the dns_name for each host' do
          expect(set_hostnames).to eq(@hosts)
          @hosts.each do |host|
            expect(host[:vmhostname]).to eq(host[:dns_name])
            expect(host[:vmhostname]).to eq(host.hostname)
          end
        end

        it 'sets the the vmhostname to the beaker config name for each host' do
          options[:use_beaker_hostnames] = true
	  @hosts.each do |host|
            host.instance_eval("@name = 'prettyponyprincess'")
	  end
          expect(set_hostnames).to eq(@hosts)
          @hosts.each do |host|
            expect(host[:vmhostname]).not_to eq(nil)
            expect(host[:vmhostname]).to eq(host.name)
            expect(host[:vmhostname]).to eq(host.hostname)
          end
        end

      end
    end

    describe '#backoff_sleep' do
      it "should call sleep 1024 times at attempt 10" do
        expect_any_instance_of( Object ).to receive(:sleep).with(1024)
        aws.backoff_sleep(10)
      end
    end

    describe '#public_key' do
      subject(:public_key) { aws.public_key }

      it "retrieves contents from local ~/.ssh/id_rsa.pub file" do
        # Stub calls to file read/exists
        key_value = 'foobar_Rsa'
        allow(File).to receive(:exist?).with(/id_dsa.pub/) { false }
        allow(File).to receive(:exist?).with(/id_dsa/) { false }
        allow(File).to receive(:exist?).with(/id_rsa.pub/) { true }
        allow(File).to receive(:exist?).with(/id_rsa/) { true }
        allow(File).to receive(:read).with(/id_rsa.pub/) { key_value }

        # Should return contents of allow( previously ).to receivebed id_rsa.pub
        expect(public_key).to be === key_value
      end

      it "retrieves contents from local ~/.ssh/id_dsa.pub file" do
        # Stub calls to file read/exists
        key_value = 'foobar_Dsa'
        allow(File).to receive(:exist?).with(/id_rsa.pub/) { false }
        allow(File).to receive(:exist?).with(/id_rsa/) { false }
        allow(File).to receive(:exist?).with(/id_dsa.pub/) { true }
        allow(File).to receive(:exist?).with(/id_dsa/) { true }
        allow(File).to receive(:read).with(/id_dsa.pub/) { key_value }

        expect(public_key).to be === key_value
      end

      it "should return an error if the files do not exist" do
        allow(File).to receive(:exist?).with(/id_[dr]sa.pub/) { false }
        allow(File).to receive(:exist?).with(/id_[dr]sa/) { false }
        expect { public_key }.to raise_error(RuntimeError, /Expected to find a public key/)
      end

      it "uses options-provided keys" do
        opts = aws.instance_variable_get( :@options )
        opts[:ssh][:keys] = ['fake_key1', 'fake_key2']
        aws.instance_variable_set( :@options, opts )

        key_value = 'foobar_Custom2'
        allow(File).to receive(:exist?).with(anything) { false }
        allow(File).to receive(:exist?).with(/fake_key2/) { true }
        allow(File).to receive(:read).with(/fake_key2/) { key_value }

        expect(public_key).to be === key_value
      end
    end

    describe '#key_name' do
      it 'returns a key name from the local hostname' do
        # Mock out the hostname and local user calls
        expect( Socket ).to receive(:gethostname) { "foobar" }
        expect( aws ).to receive(:local_user) { "bob" }

        # Should match the expected composite key name
        expect(aws.key_name).to match(/^Beaker-bob-foobar-/)
      end

      it 'uses the generated random string from :aws_keyname_modifier' do
        expect(aws.key_name).to match(/#{options[:aws_keyname_modifier]}/)
      end

      it 'uses nanosecond time value to make key name collision harder' do
        options[:timestamp] = Time.now
        nanosecond_value = options[:timestamp].strftime("%N")
        expect(aws.key_name).to match(/#{nanosecond_value}/)
      end
    end

    describe '#local_user' do
      it 'returns ENV["USER"]' do
        stub_const('ENV', ENV.to_hash.merge('USER' => 'SuperUser'))
        expect(aws.local_user).to eq("SuperUser")
      end
    end

    describe '#ensure_key_pair' do
      let( :region ) { double('region', :name => 'test_region_name') }
      subject(:ensure_key_pair) { aws.ensure_key_pair(region) }
      let( :key_name ) { "Beaker-rspec-SUT" }

      it 'deletes the given keypair, then recreates it' do
        allow( aws ).to receive( :key_name ).and_return(key_name)

        expect( aws ).to receive( :delete_key_pair ).with( region, key_name).once.ordered
        expect( aws ).to receive( :create_new_key_pair ).with( region, key_name).once.ordered
        ensure_key_pair
      end
    end

    describe '#delete_key_pair_all_regions' do
      before(:each) do
        allow(aws).to receive(:my_key_pairs).and_return(region_keypairs)
      end

      after(:each) do
        aws.delete_key_pair_all_regions
      end

      let(:region_keypairs) do
        {
          'test1' => ['key1', 'key2', 'key3'],
          'test2' => ['key4', 'key5', 'key6'],
        }
      end

      it 'calls delete_key_pair over all regions' do
        region_keypairs.each do |region, keyname_array|
          keyname_array.each do |keyname|
            expect(aws).to receive(:delete_key_pair).with(region, keyname)
          end
        end
      end
    end

    describe '#my_key_pairs' do
      let(:regions) { ['name1', 'name2'] }
      let(:mock_clients) { regions.map { |r| [r, instance_double(Aws::EC2::Client)] }.to_h }
      let(:default_key_name) { 'test_pair_6193' }

      before(:each) do
        allow(aws).to receive(:regions).and_return(regions)
        allow(aws).to receive(:key_name).and_return(default_key_name)

        regions.each do |region|
          allow(aws).to receive(:client).with(region).and_return(mock_clients[region])
        end
      end

      it 'uses the default keyname if no filter is given' do
        regions.each do |region|
          expect(mock_clients[region]).to receive(:describe_key_pairs).with(
            :filters => [{ :name => 'key-name', :values => [default_key_name] }]
          ).and_return(instance_double(Aws::EC2::Types::DescribeKeyPairsResult, :key_pairs => []))
        end

        aws.my_key_pairs()
      end

      it 'uses the filter passed if given' do
        name_filter = 'filter_pair_1597'
        filter_pattern = "#{name_filter}-*"

        regions.each do |region|
          expect(mock_clients[region]).to receive(:describe_key_pairs).with(
            :filters => [{ :name => 'key-name', :values => [filter_pattern] }]
          ).and_return(instance_double(Aws::EC2::Types::DescribeKeyPairsResult, :key_pairs => []))
        end

        aws.my_key_pairs(name_filter)
      end
    end

    describe '#delete_key_pair' do
      let(:region) { 'test_region_name' }
      let(:mock_client) { instance_double(Aws::EC2::Client) }
      let(:pair_name) { 'pair1' }

      before(:each) do
        allow(aws).to receive(:client).with(region).and_return(mock_client)
        allow(mock_client).to receive(:describe_key_pairs).with(
          :key_names => [pair_name]
        ).and_return(instance_double(Aws::EC2::Types::DescribeKeyPairsResult, :key_pairs => result))
      end

      after(:each) do
        aws.delete_key_pair(region, pair_name)
      end

      context 'when the keypair exists' do
        let(:result) { [instance_double(Aws::EC2::Types::KeyPairInfo)] }

        it 'deletes the keypair' do
          expect(mock_client).to receive(:delete_key_pair).with(:key_name => pair_name)
        end
      end

      context 'when the keypair does not exist' do
        let(:result) { [] }

        it 'does not try to delete the keypair' do
          expect(mock_client).not_to receive(:delete_key_pair)
        end
      end
    end

    describe '#create_new_key_pair' do
      let(:region) { 'test_region_name' }
      let(:ssh_string) { 'ssh_string_test_0867' }
      let(:pair) { instance_double(Aws::EC2::Types::KeyPairInfo) }
      let(:pair_name) { 'pair_name_1555432' }
      let(:mock_client) { instance_double(Aws::EC2::Client) }

      before :each do
        allow(aws).to receive(:client).with(region).and_return(mock_client)
        allow(aws).to receive(:public_key).and_return(ssh_string)
        allow(mock_client).to receive(:import_key_pair).with(
          :key_name            => pair_name,
          :public_key_material => ssh_string,
        )
        allow(mock_client).to receive(:wait_until).with(:key_pair_exists, any_args)
      end

      it 'imports the key given from public_key' do
        expect(mock_client).to receive(:import_key_pair).with(
          :key_name            => pair_name,
          :public_key_material => ssh_string,
        )

        aws.create_new_key_pair(region, pair_name)
      end

      it 'raises an exception if subsequent keypair check is false' do
        allow(mock_client).to receive(:wait_until).with(:key_pair_exists, any_args).and_raise(Aws::Waiters::Errors::WaiterFailed)
        expect {
          aws.create_new_key_pair(region, pair_name)
        }.to raise_error(RuntimeError,
          "AWS key pair #{pair_name} can not be queried, even after import")
      end
    end

    describe '#group_id' do
      it 'should return a predicatable group_id from a port list' do
        expect(aws.group_id([22, 1024])).to eq("Beaker-2799478787")
      end

      it 'should return a predicatable group_id from an empty list' do
        expect { aws.group_id([]) }.to raise_error(ArgumentError, "Ports list cannot be nil or empty")
      end
    end

    describe '#ensure_group' do
      let(:vpc) { instance_double(Aws::EC2::Types::Vpc, :vpc_id => 1) }
      let(:ports) { [22, 80, 8080] }
      let(:default_sg_cidr_ips) { ['0.0.0.0/0'] }

      subject(:ensure_group) { aws.ensure_group(vpc, ports) }

      let(:mock_client) { instance_double(Aws::EC2::Client) }

      before :each do
        allow(aws).to receive(:client).and_return(mock_client)
      end

      let(:security_group_result) do
        instance_double(Aws::EC2::Types::DescribeSecurityGroupsResult, :security_groups => [group])
      end

      context 'for an existing group' do
        let(:group) { instance_double(Aws::EC2::Types::SecurityGroup, :group_name => 'Beaker-1521896090') }

        it 'returns group from vpc lookup' do
          allow(mock_client).to receive(:describe_security_groups).with(any_args).and_return(security_group_result)
          expect(ensure_group).to eq(group)
        end

        context 'during group lookup' do
          it 'performs group_id lookup for ports' do
            expect(aws).to receive(:group_id).with(ports)
            allow(mock_client).to receive(:describe_security_groups).with(any_args).and_return(security_group_result)
            expect(ensure_group).to eq(group)
          end

          it 'filters on group_id' do
            allow(mock_client).to receive(:describe_security_groups).with(:filters => include({:name => 'group-name', :values => ['Beaker-1521896090']})).and_return(security_group_result)
            expect(ensure_group).to eq(group)
          end
        end
      end

      context 'when group does not exist' do
        let(:group) { nil }

        it 'creates group if group.nil?' do
          expect(aws).to receive(:create_group).with(vpc, ports, default_sg_cidr_ips).and_return(group)
          allow(mock_client).to receive(:describe_security_groups).with(any_args).and_return(security_group_result)
          expect(ensure_group).to eq(group)
        end
      end
    end

    describe '#create_group' do
      let(:group_vpc_id) { 'vpc-someid' }
      let(:rv) { instance_double(Aws::EC2::Types::Vpc, :vpc_id => group_vpc_id) }
      let(:ports) { [22, 80, 8080] }
      subject(:create_group) { aws.create_group(rv, ports) }

      let(:group) { instance_double(Aws::EC2::Types::SecurityGroup, :group_id => 1) }
      let(:mock_client) { instance_double(Aws::EC2::Client) }

      before(:each) do
        allow(aws).to receive(:client).and_return(mock_client)
      end

      it 'returns a newly created group' do
        allow(mock_client).to receive(:create_security_group).with(any_args).and_return(group)
        allow(mock_client).to receive(:authorize_security_group_ingress).with(include(:group_id => group.group_id)).at_least(:once)
        expect(create_group).to eq(group)
      end

      it 'requests group_id for ports given' do
        expect(aws).to receive(:group_id).with(ports)
        allow(mock_client).to receive(:create_security_group).with(any_args).and_return(group)
        allow(mock_client).to receive(:authorize_security_group_ingress).with(include(:group_id => group.group_id)).at_least(:once)
        expect(create_group).to eq(group)
      end

      it 'creates group with expected arguments' do
        group_name = "Beaker-1521896090"
        group_desc = "Custom Beaker security group for #{ports.to_a}"

        expect(mock_client).to receive(:create_security_group).with(
          :group_name => group_name,
          :description => group_desc,
        ).and_return(group)
        allow(mock_client).to receive(:authorize_security_group_ingress).with(include(:group_id => group.group_id)).at_least(:once)
        expect(create_group).to eq(group)
      end

      context 'it is called with VPC as first param' do
        it 'creates group with expected arguments including vpc id' do
          group_name = "Beaker-1521896090"
          group_desc = "Custom Beaker security group for #{ports.to_a}"

          allow(rv).to receive(:is_a?).with(String).and_return(false)
          allow(rv).to receive(:is_a?).with(Aws::EC2::Types::Vpc).and_return(true)

          expect(mock_client).to receive(:create_security_group).with(
            :group_name => group_name,
            :description => group_desc,
            :vpc_id => group_vpc_id,
          ).and_return(group)
          allow(mock_client).to receive(:authorize_security_group_ingress).with(include(:group_id => group.group_id)).at_least(:once)
          expect(create_group).to eq(group)
        end
      end

      it 'authorizes requested ports for group' do
        allow(mock_client).to receive(:create_security_group).with(any_args).and_return(group)

        ports.each do |port|
          expect(mock_client).to receive(:authorize_security_group_ingress).with(include(:to_port => port)).once
        end
        expect(create_group).to eq(group)
      end

      context 'security group CIDRs are passed' do
        let(:sg_cidr_ips) { ['172.28.40.0/24', '172.20.112.0/20'] }
        subject(:create_group_with_cidr) { aws.create_group(rv, ports, sg_cidr_ips) }

        it 'authorizes requested CIDR for group' do
          allow(mock_client).to receive(:create_security_group).with(any_args).and_return(group)

          sg_cidr_ips.each do |cidr_ip|
            expect(mock_client).to receive(:authorize_security_group_ingress).with(include(:cidr_ip => cidr_ip)).exactly(3).times
          end

          expect(create_group_with_cidr).to eq(group)
        end
      end
    end

    describe '#load_fog_credentials' do
      # Receive#and_call_original below allows us to test the core load_fog_credentials method
      let(:dot_fog) { '.fog' }
      subject(:load_fog_credentials) { aws.load_fog_credentials(dot_fog) }

      before do
        expect(File).to receive(:exist?).with(dot_fog) { true }
      end

      it 'returns loaded fog credentials' do
        creds = {:access_key_id => 'awskey', :secret_access_key => 'awspass', :session_token => nil}
        fog_hash = {:default => {:aws_access_key_id => 'awskey', :aws_secret_access_key => 'awspass'}}
        expect(aws).to receive(:load_fog_credentials).and_call_original
        expect(YAML).to receive(:load_file).and_return(fog_hash)
        expect(load_fog_credentials).to have_attributes(creds)
      end

      it 'returns loaded fog credentials with session token' do
        creds = {:access_key_id => 'awskey', :secret_access_key => 'awspass', :session_token => 'sometoken'}
        fog_hash = {:default => {:aws_access_key_id => 'awskey', :aws_secret_access_key => 'awspass', :aws_session_token => 'sometoken'}}
        expect(aws).to receive(:load_fog_credentials).and_call_original
        expect(YAML).to receive(:load_file).and_return(fog_hash)
        expect(load_fog_credentials).to have_attributes(creds)
      end

      context 'raises errors' do
        it 'if missing access_key credential' do
          fog_hash = {:default => {:aws_secret_access_key => 'awspass'}}
          err_text = "You must specify an aws_access_key_id in your .fog file (#{dot_fog}) for ec2 instances!"
          expect(aws).to receive(:load_fog_credentials).and_call_original
          expect(YAML).to receive(:load_file).and_return(fog_hash)
          expect { load_fog_credentials }.to raise_error(err_text)
        end

        it 'if missing secret_key credential' do
          dot_fog = '.fog'
          fog_hash = {:default => {:aws_access_key_id => 'awskey'}}
          err_text = "You must specify an aws_secret_access_key in your .fog file (#{dot_fog}) for ec2 instances!"
          expect(aws).to receive(:load_fog_credentials).and_call_original
          expect(YAML).to receive(:load_file).and_return(fog_hash)
          expect { load_fog_credentials }.to raise_error(err_text)
        end
      end
    end

    describe 'test_split_install' do
      it 'does not add port 8143 if master, dashboard and database are on the same host' do
        @hosts = [@hosts[0]]
        @hosts[0][:roles] = ["master", "dashboard", "database"]
        allow(aws).to receive(:test_split_install)
        expect(@hosts[0]).not_to have_key(:additional_ports)
        aws
      end

      it 'does not add port 8143 if host does not have master, dashboard or database at all' do
        @hosts = [@hosts[0]]
        @hosts[0][:roles] = ["agent", "frictionless"]
        allow(aws).to receive(:test_split_install)
        expect(@hosts[0]).not_to have_key(:additional_ports)
        aws
      end

      it 'adds port 8143 to all the hosts for split install that has either master, dashboard or database' do
        @hosts = [@hosts[0], @hosts[1], @hosts[2], @hosts[3]]
        @hosts[0][:roles] = ["master"]
        @hosts[1][:roles] = ["dashboard"]
        @hosts[2][:roles] = ["database"]
        @hosts[3][:roles] = ["agent"]
        allow(aws).to receive(:test_split_install)
        expect(@hosts[0]).to have_key(:additional_ports)
        expect(@hosts[0][:additional_ports]).to include(8143)
        expect(@hosts[1]).to have_key(:additional_ports)
        expect(@hosts[1][:additional_ports]).to include(8143)
        expect(@hosts[2]).to have_key(:additional_ports)
        expect(@hosts[2][:additional_ports]).to include(8143)
        expect(@hosts[3]).not_to have_key(:additional_ports)
        aws
      end
    end
  end
end
