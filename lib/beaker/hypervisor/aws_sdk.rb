require 'aws-sdk-ec2'
require 'aws-sdk-core/waiters'
require 'set'
require 'zlib'
require 'beaker/hypervisor/ec2_helper'

class Aws::EC2::Types::Instance
  def ip_address
    public_ip_address || private_ip_address
  end
end

module Beaker
  # This is an alternate EC2 driver that implements direct API access using
  # Amazon's AWS-SDK library: {http://aws.amazon.com/documentation/sdkforruby/ SDK For Ruby}
  #
  # It is built for full control, to reduce any other layers beyond the pure
  # vendor API.
  class AwsSdk < Beaker::Hypervisor
    ZOMBIE = 3 #anything older than 3 hours is considered a zombie
    PING_SECURITY_GROUP_NAME = 'beaker-ping'
    attr_reader :default_region

    # Initialize AwsSdk hypervisor driver
    #
    # @param [Array<Beaker::Host>] hosts Array of Beaker::Host objects
    # @param [Hash<String, String>] options Options hash
    def initialize(hosts, options)
      @hosts = hosts
      @options = options
      @logger = options[:logger]
      @default_region = ENV['AWS_REGION'] || 'us-west-2'

      # Get AWS credentials
      creds = options[:use_fog_credentials] ? load_credentials() : nil

      config = {
        :credentials   => creds,
        :logger        => Logger.new($stdout),
        :log_level     => :debug,
        :log_formatter => Aws::Log::Formatter.colored,
        :retry_limit   => 12,
        :region        => ENV['AWS_REGION'] || 'us-west-2'
      }.delete_if{ |k,v| v.nil? }
      Aws.config.update(config)

      @client = {}
      @client.default_proc = proc do |hash, key|
        hash[key] = Aws::EC2::Client.new(:region => key)
      end

      test_split_install()
    end

    def client(region = default_region)
      @client[region]
    end

    # Provision all hosts on EC2 using the Aws::EC2 API
    #
    # @return [void]
    def provision
      start_time = Time.now

      # Perform the main launch work
      launch_all_nodes()

      # Add metadata tags to each instance
      # tagging early as some nodes take longer
      # to initialize and terminate before it has
      # a chance to provision
      add_tags()

      # adding the correct security groups to the
      # network interface, as during the `launch_all_nodes()`
      # step they never get assigned, although they get created
      modify_network_interface()

      wait_for_status_netdev()

      # Grab the ip addresses and dns from EC2 for each instance to use for ssh
      populate_dns()

      #enable root if user is not root
      enable_root_on_hosts()

      # Set the hostname for each box
      set_hostnames()

      # Configure /etc/hosts on each host
      configure_hosts()

      @logger.notify("aws-sdk: Provisioning complete in #{Time.now - start_time} seconds")

      nil #void
    end

    def regions
      @regions ||= client.describe_regions.regions.map(&:region_name)
    end

    # Kill all instances.
    #
    # @param instances [Enumerable<Aws::EC2::Types::Instance>]
    # @return [void]
    def kill_instances(instances)
      running_instances = instances.compact.select do |instance|
        instance_by_id(instance.instance_id).state.name == 'running'
      end
      instance_ids = running_instances.map(&:instance_id)

      return nil if instance_ids.empty?

      @logger.notify("aws-sdk: killing EC2 instance(s) #{instance_ids.join(', ')}")
      client.terminate_instances(:instance_ids => instance_ids)

      nil
    end

    # Cleanup all earlier provisioned hosts on EC2 using the Aws::EC2 library
    #
    # It goes without saying, but a #cleanup does nothing without a #provision
    # method call first.
    #
    # @return [void]
    def cleanup
      # Provisioning should have set the host 'instance' values.
      kill_instances(@hosts.map{ |h| h['instance'] }.select{ |x| !x.nil? })
      delete_key_pair_all_regions()
      nil
    end

    # Print instances to the logger. Instances will be from all regions
    # associated with provided key name and limited by regex compared to
    # instance status. Defaults to running instances.
    #
    # @param [String] key The key_name to match for
    # @param [Regex] status The regular expression to match against the instance's status
    def log_instances(key = key_name, status = /running/)
      instances = []
      regions.each do |region|
        @logger.debug "Reviewing: #{region}"
        client(region).describe_instances.reservations.each do |reservation|
          reservation.instances.each do |instance|
            if (instance.key_name =~ /#{key}/) and (instance.state.name =~ status)
              instances << instance
            end
          end
        end
      end
      output = ""
      instances.each do |instance|
        dns_name = instance.public_dns_name || instance.private_dns_name
        output << "#{instance.instance_id} keyname: #{instance.key_name}, dns name: #{dns_name}, private ip: #{instance.private_ip_address}, ip: #{instance.public_ip_address}, launch time #{instance.launch_time}, status: #{instance.state.name}\n"
      end
      @logger.notify("aws-sdk: List instances (keyname: #{key})")
      @logger.notify("#{output}")
    end

    # Provided an id return an instance object.
    # Instance object will respond to methods described here: {http://docs.aws.amazon.com/AWSRubySDK/latest/AWS/EC2/Instance.html AWS Instance Object}.
    # @param [String] id The id of the instance to return
    # @return [Aws::EC2::Types::Instance] An Aws::EC2 instance object
    def instance_by_id(id)
      client.describe_instances(:instance_ids => [id]).reservations.first.instances.first
    end

    # Return all instances currently on ec2.
    # @see AwsSdk#instance_by_id
    # @return [Array<Aws::Ec2::Types::Instance>] An array of Aws::EC2 instance objects
    def instances
      client.describe_instances.reservations.map(&:instances).flatten
    end

    # Provided an id return a VPC object.
    # VPC object will respond to methods described here: {http://docs.aws.amazon.com/AWSRubySDK/latest/AWS/EC2/VPC.html AWS VPC Object}.
    # @param [String] id The id of the VPC to return
    # @return [Aws::EC2::Types::Vpc] An Aws::EC2 vpc object
    def vpc_by_id(id)
      client.describe_vpcs(:vpc_ids => [id]).vpcs.first
    end

    # Return all VPCs currently on ec2.
    # @see AwsSdk#vpc_by_id
    # @return [Array<Aws::EC2::Types::Vpc>] An array of Aws::EC2 vpc objects
    def vpcs
      client.describe_vpcs.vpcs
    end

    # Provided an id return a security group object
    # Security object will respond to methods described here: {http://docs.aws.amazon.com/AWSRubySDK/latest/AWS/EC2/SecurityGroup.html AWS SecurityGroup Object}.
    # @param [String] id The id of the security group to return
    # @return [Aws::EC2::Types::SecurityGroup] An Aws::EC2 security group object
    def security_group_by_id(id)
      client.describe_security_groups(:group_ids => [id]).security_groups.first
    end

    # Return all security groups currently on ec2.
    # @see AwsSdk#security_goup_by_id
    # @return [Array<Aws::EC2::Types::SecurityGroup>] An array of Aws::EC2 security group objects
    def security_groups
      client.describe_security_groups.security_groups
    end

    # Shutdown and destroy ec2 instances idenfitied by key that have been alive
    # longer than ZOMBIE hours.
    #
    # @param [Integer] max_age The age in hours that a machine needs to be older than to be considered a zombie
    # @param [String] key The key_name to match for
    def kill_zombies(max_age = ZOMBIE, key = key_name)
      @logger.notify("aws-sdk: Kill Zombies! (keyname: #{key}, age: #{max_age} hrs)")

      instances_to_kill = []

      time_now = Time.now.getgm #ec2 uses GM time

      #examine all available regions
      regions.each do |region|
        @logger.debug "Reviewing: #{region}"

        client(region).describe_instances.reservations.each do |reservation|
          reservation.instances.each do |instance|
            if (instance.key_name =~ /#{key}/)
              @logger.debug "Examining #{instance.instance_id} (keyname: #{instance.key_name}, launch time: #{instance.launch_time}, state: #{instance.state.name})"
              if ((time_now - instance.launch_time) >  max_age*60*60) and instance.state.name !~ /terminated/
                @logger.debug "Kill! #{instance.instance_id}: #{instance.key_name} (Current status: #{instance.state.name})"
                instances_to_kill << instance
              end
            end
          end
        end
      end

      kill_instances(instances_to_kill)
      delete_key_pair_all_regions(key_name_prefix)

      @logger.notify "#{key}: Killed #{instances_to_kill.length} instance(s)"
    end

    # Destroy any volumes marked 'available', INCLUDING THOSE YOU DON'T OWN!  Use with care.
    def kill_zombie_volumes
      # Occasionaly, tearing down ec2 instances leaves orphaned EBS volumes behind -- these stack up quickly.
      # This simply looks for EBS volumes that are not in use
      @logger.notify("aws-sdk: Kill Zombie Volumes!")
      volume_count = 0

      regions.each do |region|
        @logger.debug "Reviewing: #{region}"
        available_volumes = client(region).describe_volumes(
          :filters => [
            { :name => 'status', :values => ['available'], }
          ]
        ).volumes

        available_volumes.each do |volume|
          begin
            client(region).delete_volume(:volume_id => volume.id)
            volume_count += 1
          rescue Aws::EC2::Errors::InvalidVolume::NotFound => e
            @logger.debug "Failed to remove volume: #{volume.id} #{e}"
          end
        end
      end

      @logger.notify "Freed #{volume_count} volume(s)"
    end

    # Create an EC2 instance for host, tag it, and return it.
    #
    # @return [void]
    # @api private
    def create_instance(host, ami_spec, subnet_id)
      amitype = host['vmname'] || host['platform']
      amisize = host['amisize'] || 'm1.small'
      vpc_id = host['vpc_id'] || @options['vpc_id'] || nil
      host['sg_cidr_ips'] = host['sg_cidr_ips'] || '0.0.0.0/0';
      sg_cidr_ips = host['sg_cidr_ips'].split(',')
      assoc_pub_ip_addr = host['associate_public_ip_address']

      if vpc_id && !subnet_id
        raise RuntimeError, "A subnet_id must be provided with a vpc_id"
      end
      
      if assoc_pub_ip_addr && !subnet_id
        raise RuntimeError, "A subnet_id must be provided when configuring assoc_pub_ip_addr"
      end

      # Use snapshot provided for this host
      image_type = host['snapshot']
      raise RuntimeError, "No snapshot/image_type provided for EC2 provisioning" unless image_type

      ami = ami_spec[amitype]
      ami_region = ami[:region]

      # Main region object for ec2 operations
      region = ami_region

      # If we haven't defined a vpc_id then we use the default vpc for the provided region
      unless vpc_id
        @logger.notify("aws-sdk: filtering available vpcs in region by 'isDefault'")

        default_vpcs = client(region).describe_vpcs(:filters => [{:name => 'isDefault', :values => ['true']}])
        vpc_id = if default_vpcs.vpcs.empty?
                   nil
                 else
                   default_vpcs.vpcs.first.vpc_id
                 end
      end

      # Grab the vpc object based upon provided id
      vpc = vpc_id ? client(region).describe_vpcs(:vpc_ids => [vpc_id]).vpcs.first : nil

      # Grab image object
      image_id = ami[:image][image_type.to_sym]
      @logger.notify("aws-sdk: Checking image #{image_id} exists and getting its root device")
      image = client(region).describe_images(:image_ids => [image_id]).images.first
      raise RuntimeError, "Image not found: #{image_id}" if image.nil?

      @logger.notify("Image Storage Type: #{image.root_device_type}")

      # Transform the images block_device_mappings output into a format
      # ready for a create.
      block_device_mappings = []
      if image.root_device_type == :ebs
        orig_bdm = image.block_device_mappings
        @logger.notify("aws-sdk: Image block_device_mappings: #{orig_bdm}")
        orig_bdm.each do |block_device|
          block_device_mappings << {
            :device_name => block_device.device_name,
            :ebs => {
              # Change the default size of the root volume.
              :volume_size => host['volume_size'] || block_device.ebs.volume_size,
              # This is required to override the images default for
              # delete_on_termination, forcing all volumes to be deleted once the
              # instance is terminated.
              :delete_on_termination => true,
            }
          }
        end
      end

      security_group = ensure_group(vpc || region, Beaker::EC2Helper.amiports(host), sg_cidr_ips)
      #check if ping is enabled
      ping_security_group = ensure_ping_group(vpc || region, sg_cidr_ips)

      msg = "aws-sdk: launching %p on %p using %p/%p%s" %
            [host.name, amitype, amisize, image_type,
             subnet_id ? ("in %p" % subnet_id) : '']
      @logger.notify(msg)
      config = {
        :max_count  => 1,
        :min_count  => 1,
        :image_id   => image_id,
        :monitoring => {
          :enabled => true,
        },
        :key_name => ensure_key_pair(region).key_pairs.first.key_name,
        :instance_type => amisize,
        :disable_api_termination => false,
        :instance_initiated_shutdown_behavior => "terminate",
      }
      if assoc_pub_ip_addr
        # this never gets created, so they end up with
        # default security group which only allows for
        # ssh access from outside world which
        # doesn't work well with remote devices etc.
        config[:network_interfaces] = [{
          :subnet_id => subnet_id,
          :groups => [security_group.group_id, ping_security_group.group_id],
          :device_index => 0,
          :associate_public_ip_address => assoc_pub_ip_addr,
        }]
      else
        config[:subnet_id] = subnet_id
      end
      config[:block_device_mappings] = block_device_mappings if image.root_device_type == :ebs
      reservation = client(region).run_instances(config)
      reservation.instances.first
    end

    # For each host, create an EC2 instance in one of the specified
    # subnets and push it onto instances_created.  Each subnet will be
    # tried at most once for each host, and more than one subnet may
    # be tried if capacity constraints are encountered.  Each Hash in
    # instances_created will contain an :instance and :host value.
    #
    # @param hosts [Enumerable<Host>]
    # @param subnets [Enumerable<String>]
    # @param ami_spec [Hash]
    # @param instances_created Enumerable<Hash{Symbol=>EC2::Instance,Host}>
    # @return [void]
    # @api private
    def launch_nodes_on_some_subnet(hosts, subnets, ami_spec, instances_created)
      # Shuffle the subnets so we don't always hit the same one
      # first, and cycle though the subnets independently of the
      # host, so we stick with one that's working.  Try each subnet
      # once per-host.
      if subnets.nil? or subnets.empty?
        return
      end
      subnet_i = 0
      shuffnets = subnets.shuffle
      hosts.each do |host|
        instance = nil
        shuffnets.length.times do
          begin
            subnet_id = shuffnets[subnet_i]
            instance = create_instance(host, ami_spec, subnet_id)
            instances_created.push({:instance => instance, :host => host})
            break
          rescue Aws::EC2::Errors::InsufficientInstanceCapacity
            @logger.notify("aws-sdk: hit #{subnet_id} capacity limit; moving on")
            subnet_i = (subnet_i + 1) % shuffnets.length
          end
        end
        if instance.nil?
          raise RuntimeError, "unable to launch host in any requested subnet"
        end
      end
    end

    # Create EC2 instances for all hosts, tag them, and wait until
    # they're running.  When a host provides a subnet_id, create the
    # instance in that subnet, otherwise prefer a CONFIG subnet_id.
    # If neither are set but there is a CONFIG subnet_ids list,
    # attempt to create the host in each specified subnet, which might
    # fail due to capacity constraints, for example.  Specifying both
    # a CONFIG subnet_id and subnet_ids will provoke an error.
    #
    # @return [void]
    # @api private
    def launch_all_nodes
      @logger.notify("aws-sdk: launch all hosts in configuration")
      ami_spec = YAML.load_file(@options[:ec2_yaml])["AMI"]
      global_subnet_id = @options['subnet_id']
      global_subnets = @options['subnet_ids']
      if global_subnet_id and global_subnets
        raise RuntimeError, 'Config specifies both subnet_id and subnet_ids'
      end
      no_subnet_hosts = []
      specific_subnet_hosts = []
      some_subnet_hosts = []
      @hosts.each do |host|
        if global_subnet_id or host['subnet_id']
          specific_subnet_hosts.push(host)
        elsif global_subnets
          some_subnet_hosts.push(host)
        else
          no_subnet_hosts.push(host)
        end
      end
      instances = [] # Each element is {:instance => i, :host => h}
      begin
        @logger.notify("aws-sdk: launch instances not particular about subnet")
        launch_nodes_on_some_subnet(some_subnet_hosts, global_subnets, ami_spec,
                                    instances)
        @logger.notify("aws-sdk: launch instances requiring a specific subnet")
        specific_subnet_hosts.each do |host|
          subnet_id = host['subnet_id'] || global_subnet_id
          instance = create_instance(host, ami_spec, subnet_id)
          instances.push({:instance => instance, :host => host})
        end
        @logger.notify("aws-sdk: launch instances requiring no subnet")
        no_subnet_hosts.each do |host|
          instance = create_instance(host, ami_spec, nil)
          instances.push({:instance => instance, :host => host})
        end
        wait_for_status(:running, instances)
      rescue Exception => ex
        @logger.notify("aws-sdk: exception #{ex.class}: #{ex}")
        kill_instances(instances.map{|x| x[:instance]})
        raise ex
      end
      # At this point, all instances should be running since wait
      # either returns on success or throws an exception.
      if instances.empty?
        raise RuntimeError, "Didn't manage to launch any EC2 instances"
      end
      # Assign the now known running instances to their hosts.
      instances.each {|x| x[:host]['instance'] = x[:instance]}
      nil
    end

    # Wait until all instances reach the desired state.  Each Hash in
    # instances must contain an :instance and :host value.
    #
    # @param state_name [String] EC2 state to wait for, 'running', 'stopped', etc.
    # @param instances Enumerable<Hash{Symbol=>EC2::Instance,Host}>
    # @param block [Proc] more complex checks can be made by passing a
    #                     block in.  This overrides the status parameter.
    #                     EC2::Instance objects from the hosts will be
    #                     yielded to the passed block
    # @return [void]
    # @api private
    # FIXME: rename to #wait_for_state
    def wait_for_status(state_name, instances, &block)
      # Wait for each node to reach status :running
      @logger.notify("aws-sdk: Waiting for all hosts to be #{state_name}")
      instances.each do |x|
        name = x[:host] ? x[:host].name : x[:name]
        instance = x[:instance]
        @logger.notify("aws-sdk: Wait for node #{name} to be #{state_name}")
        # Here we keep waiting for the machine state to reach 'running' with an
        # exponential backoff for each poll.
        # TODO: should probably be a in a shared method somewhere
        for tries in 1..10
          refreshed_instance = instance_by_id(instance.instance_id)

          if refreshed_instance.nil?
            @logger.debug("Instance #{name} not yet available (#{e})")
          else
            if block_given?
              test_result = yield refreshed_instance
            else
              test_result = refreshed_instance.state.name.to_s == state_name.to_s
            end
            if test_result
              x[:instance] = refreshed_instance
              # Always sleep, so the next command won't cause a throttle
              backoff_sleep(tries)
              break
            elsif tries == 10
              raise "Instance never reached state #{state_name}"
            end
          end

          backoff_sleep(tries)
        end
      end
    end

    # Handles special checks needed for netdev platforms.
    #
    # @note if any host is an netdev one, these checks will happen once across all
    #   of the hosts, and then we'll exit
    #
    # @return [void]
    # @api private
    def wait_for_status_netdev()
      @hosts.each do |host|
        if host['platform'] =~ /f5-|netscaler/
          wait_for_status(:running, @hosts)

          wait_for_status(nil, @hosts) do |instance|
            instance_status_collection = client.describe_instance_status({:instance_ids => [instance.instance_id]})
            first_instance = instance_status_collection.first[:instance_statuses].first
            first_instance[:instance_status][:status] == "ok" if first_instance
          end

          break
        end
      end
    end

    # Add metadata tags to all instances
    #
    # @return [void]
    # @api private
    def add_tags
      @hosts.each do |host|
        instance = host['instance']

        # Define tags for the instance
        @logger.notify("aws-sdk: Add tags for #{host.name}")

        tags = [
          {
            :key   => 'jenkins_build_url',
            :value => @options[:jenkins_build_url],
          },
          {
            :key   => 'Name',
            :value => host.name,
          },
          {
            :key   => 'department',
            :value => @options[:department],
          },
          {
            :key   => 'project',
            :value => @options[:project],
          },
          {
            :key   => 'created_by',
            :value => @options[:created_by],
          },
        ]

        host[:host_tags].each do |name, val|
          tags << { :key => name.to_s, :value => val }
        end

        client.create_tags(
          :resources => [instance.instance_id],
          :tags      => tags.reject { |r| r[:value].nil? },
        )
      end

      nil
    end

    # Add correct security groups to hosts network_interface
    # as during the create_instance stage it is too early in process
    # to configure
    #
    # @return [void]
    # @api private
    def modify_network_interface
      @hosts.each do |host|
        instance = host['instance']
        host['sg_cidr_ips'] = host['sg_cidr_ips'] || '0.0.0.0/0';
        sg_cidr_ips = host['sg_cidr_ips'].split(',')

        # Define tags for the instance
        @logger.notify("aws-sdk: Update network_interface for #{host.name}")

        security_group = ensure_group(instance[:network_interfaces].first, Beaker::EC2Helper.amiports(host), sg_cidr_ips)
        ping_security_group = ensure_ping_group(instance[:network_interfaces].first, sg_cidr_ips)

        client.modify_network_interface_attribute(
          :network_interface_id => "#{instance[:network_interfaces].first[:network_interface_id]}",
          :groups => [security_group.group_id, ping_security_group.group_id],
        )
      end

      nil
    end

    # Populate the hosts IP address from the EC2 dns_name
    #
    # @return [void]
    # @api private
    def populate_dns
      # Obtain the IP addresses and dns_name for each host
      @hosts.each do |host|
        @logger.notify("aws-sdk: Populate DNS for #{host.name}")
        instance = host['instance']
        host['ip'] = instance.public_ip_address || instance.private_ip_address
        host['private_ip'] = instance.private_ip_address
        host['dns_name'] = instance.public_dns_name || instance.private_dns_name
        @logger.notify("aws-sdk: name: #{host.name} ip: #{host['ip']} private_ip: #{host['private_ip']} dns_name: #{host['dns_name']}")
      end

      nil
    end

    # Return a valid /etc/hosts line for a given host
    #
    # @param [Beaker::Host] host Beaker::Host object for generating /etc/hosts entry
    # @param [Symbol] interface Symbol identifies which ip should be used for host
    # @return [String] formatted hosts entry for host
    # @api private
    def etc_hosts_entry(host, interface = :ip)
      name = host.name
      domain = get_domain_name(host)
      ip = host[interface.to_s]
      "#{ip}\t#{name} #{name}.#{domain} #{host['dns_name']}\n"
    end

    # Configure /etc/hosts for each node
    #
    # @note f5 hosts are skipped since this isn't a valid step there
    #
    # @return [void]
    # @api private
    def configure_hosts
      non_netdev_windows_hosts = @hosts.select{ |h| !(h['platform'] =~ /f5-|netscaler|windows/) }
      non_netdev_windows_hosts.each do |host|
        host_entries = non_netdev_windows_hosts.map do |h|
          h == host ? etc_hosts_entry(h, :private_ip) : etc_hosts_entry(h)
        end
        host_entries.unshift "127.0.0.1\tlocalhost localhost.localdomain\n"
        set_etc_hosts(host, host_entries.join(''))
      end
      nil
    end

    # Enables root for instances with custom username like ubuntu-amis
    #
    # @return [void]
    # @api private
    def enable_root_on_hosts
      @hosts.each do |host|
        if host['disable_root_ssh'] == true
          @logger.notify("aws-sdk: Not enabling root for instance as disable_root_ssh is set to 'true'.")
        else
          @logger.notify("aws-sdk: Enabling root ssh")
          enable_root(host)
        end
      end
    end

    # Enables root access for a host when username is not root
    #
    # @return [void]
    # @api private
    def enable_root(host)
      if host['user'] != 'root'
        if host['platform'] =~ /f5-/
          enable_root_f5(host)
        elsif host['platform'] =~ /netscaler/
          enable_root_netscaler(host)
        else
          copy_ssh_to_root(host, @options)
          enable_root_login(host, @options)
          host['user'] = 'root'
        end
        host.close
      end
    end

    # Enables root access for a host on an f5 platform
    # @note This method does not support other platforms
    #
    # @return nil
    # @api private
    def enable_root_f5(host)
      for tries in 1..10
        begin
          #This command is problematic as the F5 is not always done loading
          if host.exec(Command.new("modify sys db systemauth.disablerootlogin value false"), :acceptable_exit_codes => [0,1]).exit_code == 0 \
              and host.exec(Command.new("modify sys global-settings gui-setup disabled"), :acceptable_exit_codes => [0,1]).exit_code == 0 \
              and host.exec(Command.new("save sys config"), :acceptable_exit_codes => [0,1]).exit_code == 0
            backoff_sleep(tries)
            break
          elsif tries == 10
            raise "Instance was unable to be configured"
          end
        rescue Beaker::Host::CommandFailure => e
          @logger.debug("Instance not yet configured (#{e})")
        end
        backoff_sleep(tries)
      end
      host['user'] = 'admin'
      sha256 = Digest::SHA256.new
      password = sha256.hexdigest((1..50).map{(rand(86)+40).chr}.join.gsub(/\\/,'\&\&')) + 'password!'
      # disabling password policy to account for the enforcement level set
      # and the generated password is sometimes too `01070366:3: Bad password (admin): BAD PASSWORD: \
      # it is too simplistic/systematic`
      host.exec(Command.new('modify auth password-policy policy-enforcement disabled'))
      host.exec(Command.new("modify auth user admin password #{password}"))
      @logger.notify("f5: Configured admin password to be #{password}")
      host.close
      host['ssh'] = {:password => password}
    end

    # Enables root access for a host on an netscaler platform
    # @note This method does not support other platforms
    #
    # @return nil
    # @api private
    def enable_root_netscaler(host)
      host['ssh'] = {:password => host['instance'].instance_id}
      @logger.notify("netscaler: nsroot password is #{host['instance'].instance_id}")
    end

    # Set the :vmhostname for each host object to be the dns_name, which is accessible
    # publicly. Then configure each ec2 machine to that dns_name, so that when facter
    # is installed the facts for hostname and domain match the dns_name.
    #
    # if :use_beaker_hostnames: is true, set the :vmhostname and hostname of each ec2
    # machine to the host[:name] from the beaker hosts file.
    #
    # @return [@hosts]
    # @api private
    def set_hostnames
      if @options[:use_beaker_hostnames]
        @hosts.each do |host|
          host[:vmhostname] = host.name
          if host['platform'] =~ /el-7/
            # on el-7 hosts, the hostname command doesn't "stick" randomly
            host.exec(Command.new("hostnamectl set-hostname #{host.name}"))
          elsif host['platform'] =~ /windows/
            @logger.notify('aws-sdk: Change hostname on windows is not supported.')
          else
            next if host['platform'] =~ /f5-|netscaler/
            host.exec(Command.new("hostname #{host.name}"))
            if host['vmname'] =~ /^amazon/
              # Amazon Linux requires this to preserve host name changes across reboots.
              # http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-hostname.html
              # Also note that without an elastic ip set, while this will
              # preserve the hostname across a full shutdown/startup of the vm
              # (as opposed to a reboot) -- the ip address will have changed.
              host.exec(Command.new("sed -ie '/^HOSTNAME/ s/=.*/=#{host.name}/' /etc/sysconfig/network"))
            end
          end
        end
      else
        @hosts.each do |host|
          host[:vmhostname] = host[:dns_name]
          if host['platform'] =~ /el-7/
            # on el-7 hosts, the hostname command doesn't "stick" randomly
            host.exec(Command.new("hostnamectl set-hostname #{host.hostname}"))
          elsif host['platform'] =~ /windows/
            @logger.notify('aws-sdk: Change hostname on windows is not supported.')
          else
            next if host['platform'] =~ /ft-|netscaler/
            host.exec(Command.new("hostname #{host.hostname}"))
            if host['vmname'] =~ /^amazon/
              # See note above
              host.exec(Command.new("sed -ie '/^HOSTNAME/ s/=.*/=#{host.hostname}/' /etc/sysconfig/network"))
            end
          end
        end
      end
    end

    # Calculates and waits a back-off period based on the number of tries
    #
    # Logs each backupoff time and retry value to the console.
    #
    # @param tries [Number] number of tries to calculate back-off period
    # @return [void]
    # @api private
    def backoff_sleep(tries)
      # Exponential with some randomization
      sleep_time = 2 ** tries
      @logger.notify("aws-sdk: Sleeping #{sleep_time} seconds for attempt #{tries}.")
      sleep sleep_time
      nil
    end

    # Retrieve the public key locally from the executing users ~/.ssh directory
    #
    # @return [String] contents of public key
    # @api private
    def public_key
      keys = Array(@options[:ssh][:keys])
      keys << '~/.ssh/id_rsa'
      keys << '~/.ssh/id_dsa'
      key_file = keys.find do |key|
        key_pub = key + '.pub'
        File.exist?(File.expand_path(key_pub)) && File.exist?(File.expand_path(key))
      end

      if key_file
        @logger.debug("Using public key: #{key_file}")
      else
        raise RuntimeError, "Expected to find a public key, but couldn't in #{keys}"
      end
      File.read(File.expand_path(key_file + '.pub'))
    end

    # Generate a key prefix for key pair names
    #
    # @note This is the part of the key that will stay static between Beaker
    #   runs on the same host.
    #
    # @return [String] Beaker key pair name based on sanitized hostname
    def key_name_prefix
      safe_hostname = Socket.gethostname.gsub('.', '-')
      "Beaker-#{local_user}-#{safe_hostname}"
    end

    # Generate a reusable key name from the local hosts hostname
    #
    # @return [String] safe key name for current host
    # @api private
    def key_name
      "#{key_name_prefix}-#{@options[:aws_keyname_modifier]}-#{@options[:timestamp].strftime("%F_%H_%M_%S_%N")}"
    end

    # Returns the local user running this tool
    #
    # @return [String] username of local user
    # @api private
    def local_user
      ENV['USER']
    end

    # Creates the KeyPair for this test run
    #
    # @param region [Aws::EC2::Region] region to create the key pair in
    # @return [Aws::EC2::KeyPair] created key_pair
    # @api private
    def ensure_key_pair(region)
      pair_name = key_name()
      delete_key_pair(region, pair_name)
      create_new_key_pair(region, pair_name)
    end

    # Deletes key pairs from all regions
    #
    # @param [String] keypair_name_filter if given, will get all keypairs that match
    #   a simple {::String#start_with?} filter. If no filter is given, the basic key
    #   name returned by {#key_name} will be used.
    #
    # @return nil
    # @api private
    def delete_key_pair_all_regions(keypair_name_filter=nil)
      region_keypairs_hash = my_key_pairs(keypair_name_filter)
      region_keypairs_hash.each_pair do |region, keypair_name_array|
        keypair_name_array.each do |keypair_name|
          delete_key_pair(region, keypair_name)
        end
      end
    end

    # Gets the Beaker user's keypairs by region
    #
    # @param [String] name_filter if given, will get all keypairs that match
    #   a simple {::String#start_with?} filter. If no filter is given, the basic key
    #   name returned by {#key_name} will be used.
    #
    # @return [Hash{String=>Array[String]}] a hash of region name to
    #   an array of the keypair names that match for the filter
    # @api private
    def my_key_pairs(name_filter=nil)
      keypairs_by_region = {}
      key_name_filter = name_filter ? "#{name_filter}-*" : key_name

      regions.each do |region|
        keypairs_by_region[region] = client(region).describe_key_pairs(
          :filters => [{ :name => 'key-name', :values => [key_name_filter] }]
        ).key_pairs.map(&:key_name)
      end

      keypairs_by_region
    end

    # Deletes a given key pair
    #
    # @param [Aws::EC2::Region] region the region the key belongs to
    # @param [String] pair_name the name of the key to be deleted
    #
    # @api private
    def delete_key_pair(region, pair_name)
      kp = client(region).describe_key_pairs(:key_names => [pair_name]).key_pairs.first
      unless kp.nil?
        @logger.debug("aws-sdk: delete key pair in region: #{region}")
        client(region).delete_key_pair(:key_name => pair_name)
      end
    rescue Aws::EC2::Errors::InvalidKeyPairNotFound
      nil
    end

    # Create a new key pair for a given Beaker run
    #
    # @param [Aws::EC2::Region] region the region the key pair will be imported into
    # @param [String] pair_name the name of the key to be created
    #
    # @return [Aws::EC2::KeyPair] key pair created
    # @raise [RuntimeError] raised if AWS keypair not created
    def create_new_key_pair(region, pair_name)
      @logger.debug("aws-sdk: importing new key pair: #{pair_name}")
      client(region).import_key_pair(:key_name => pair_name, :public_key_material => public_key)

      begin
        client(region).wait_until(:key_pair_exists, { :key_names => [pair_name] }, :max_attempts => 5, :delay => 2)
      rescue Aws::Waiters::Errors::WaiterFailed
        raise RuntimeError, "AWS key pair #{pair_name} can not be queried, even after import"
      end
    end

    # Return a reproducable security group identifier based on input ports
    #
    # @param ports [Array<Number>] array of port numbers
    # @return [String] group identifier
    # @api private
    def group_id(ports)
      if ports.nil? or ports.empty?
        raise ArgumentError, "Ports list cannot be nil or empty"
      end

      unless ports.is_a? Set
        ports = Set.new(ports)
      end

      # Lolwut, #hash is inconsistent between ruby processes
      "Beaker-#{Zlib.crc32(ports.inspect)}"
    end

    # Return an existing group, or create new one
    #
    # Accepts a VPC as input for checking & creation.
    #
    # @param vpc [Aws::EC2::VPC] the AWS vpc control object
    # @param sg_cidr_ips [Array<String>] CIDRs used for outbound security group rule
    # @return [Aws::EC2::SecurityGroup] created security group
    # @api private
    def ensure_ping_group(vpc, sg_cidr_ips = ['0.0.0.0/0'])
      @logger.notify("aws-sdk: Ensure security group exists that enables ping, create if not")

      group = client.describe_security_groups(
        :filters => [
          { :name => 'group-name', :values => [PING_SECURITY_GROUP_NAME] },
          { :name => 'vpc-id', :values => [vpc.vpc_id] },
        ]
      ).security_groups.first

      if group.nil?
        group = create_ping_group(vpc, sg_cidr_ips)
      end

      group
    end

    # Return an existing group, or create new one
    #
    # Accepts a VPC as input for checking & creation.
    #
    # @param vpc [Aws::EC2::VPC] the AWS vpc control object
    # @param ports [Array<Number>] an array of port numbers
    # @param sg_cidr_ips [Array<String>] CIDRs used for outbound security group rule
    # @return [Aws::EC2::SecurityGroup] created security group
    # @api private
    def ensure_group(vpc, ports, sg_cidr_ips = ['0.0.0.0/0'])
      @logger.notify("aws-sdk: Ensure security group exists for ports #{ports.to_s}, create if not")
      name = group_id(ports)

      group = client.describe_security_groups(
        :filters => [
          { :name => 'group-name', :values => [name] },
          { :name => 'vpc-id', :values => [vpc.vpc_id] },
        ]
      ).security_groups.first

      if group.nil?
        group = create_group(vpc, ports, sg_cidr_ips)
      end

      group
    end

    # Create a new ping enabled security group
    #
    # Accepts a region or VPC for group creation.
    #
    # @param region_or_vpc [Aws::EC2::Region, Aws::EC2::VPC] the AWS region or vpc control object
    # @param sg_cidr_ips [Array<String>] CIDRs used for outbound security group rule
    # @return [Aws::EC2::SecurityGroup] created security group
    # @api private
    def create_ping_group(region_or_vpc, sg_cidr_ips = ['0.0.0.0/0'])
      @logger.notify("aws-sdk: Creating group #{PING_SECURITY_GROUP_NAME}")
      cl = region_or_vpc.is_a?(String) ? client(region_or_vpc) : client

      params = {
        :description => 'Custom Beaker security group to enable ping',
        :group_name  => PING_SECURITY_GROUP_NAME,
      }
      params[:vpc_id] = region_or_vpc.vpc_id if region_or_vpc.is_a?(Aws::EC2::Types::Vpc)

      group = cl.create_security_group(params)

      sg_cidr_ips.each do |cidr_ip|
        add_ingress_rule(
          cl,
          group,
          cidr_ip,
          '8', # 8 == ICMPv4 ECHO request
          '-1', # -1 == All ICMP codes
          'icmp',
        )
      end

      group
    end

    # Create a new security group
    #
    # Accepts a region or VPC for group creation.
    #
    # @param region_or_vpc [Aws::EC2::Region, Aws::EC2::VPC] the AWS region or vpc control object
    # @param ports [Array<Number>] an array of port numbers
    # @param sg_cidr_ips [Array<String>] CIDRs used for outbound security group rule
    # @return [Aws::EC2::SecurityGroup] created security group
    # @api private
    def create_group(region_or_vpc, ports, sg_cidr_ips = ['0.0.0.0/0'])
      name = group_id(ports)
      @logger.notify("aws-sdk: Creating group #{name} for ports #{ports.to_s}")
      @logger.notify("aws-sdk: Creating group #{name} with CIDR IPs #{sg_cidr_ips.to_s}")
      cl = region_or_vpc.is_a?(String) ? client(region_or_vpc) : client

      params = {
        :description => "Custom Beaker security group for #{ports.to_a}",
        :group_name  => name,
      }

      params[:vpc_id] = region_or_vpc.vpc_id if region_or_vpc.is_a?(Aws::EC2::Types::Vpc)

      group = cl.create_security_group(params)

      unless ports.is_a? Set
        ports = Set.new(ports)
      end

      sg_cidr_ips.each do |cidr_ip|
        ports.each do |port|
          add_ingress_rule(cl, group, cidr_ip, port, port)
        end
      end

      group
    end

    # Authorizes connections from certain CIDR to a range of ports
    #
    # @param cl [Aws::EC2::Client]
    # @param sg_group [Aws::EC2::SecurityGroup] the AWS security group
    # @param cidr_ip [String] CIDR used for outbound security group rule
    # @param from_port [String] Starting Port number in the range
    # @param to_port [String] Ending Port number in the range
    # @return [void]
    # @api private
    def add_ingress_rule(cl, sg_group, cidr_ip, from_port, to_port, protocol = 'tcp')
      cl.authorize_security_group_ingress(
        :cidr_ip     => cidr_ip,
        :ip_protocol => protocol,
        :from_port   => from_port,
        :to_port     => to_port,
        :group_id    => sg_group.group_id,
      )
    end

    # Return a hash containing AWS credentials
    #
    # @return [Hash<Symbol, String>] AWS credentials
    # @api private
    def load_credentials
      return load_env_credentials if load_env_credentials.set?
      load_fog_credentials(@options[:dot_fog])
    end

    # Return AWS credentials loaded from environment variables
    #
    # @param prefix [String] environment variable prefix
    # @return [Aws::Credentials] ec2 credentials
    # @api private
    def load_env_credentials(prefix='AWS')
      Aws::Credentials.new(
        ENV["#{prefix}_ACCESS_KEY_ID"],
        ENV["#{prefix}_SECRET_ACCESS_KEY"],
        ENV["#{prefix}_SESSION_TOKEN"]
      )
    end

    # Return a hash containing the fog credentials for EC2
    #
    # @param dot_fog [String] dot fog path
    # @return [Aws::Credentials] ec2 credentials
    # @api private
    def load_fog_credentials(dot_fog = '.fog')
      default = get_fog_credentials(dot_fog)

      raise "You must specify an aws_access_key_id in your .fog file (#{dot_fog}) for ec2 instances!" unless default[:aws_access_key_id]
      raise "You must specify an aws_secret_access_key in your .fog file (#{dot_fog}) for ec2 instances!" unless default[:aws_secret_access_key]

      Aws::Credentials.new(
        default[:aws_access_key_id],
        default[:aws_secret_access_key],
        default[:aws_session_token]
      )
    end

    # Adds port 8143 to host[:additional_ports]
    # if master, database and dashboard are not on same instance
    def test_split_install
      @hosts.each do |host|
        mono_roles = ['master', 'database', 'dashboard']
        roles_intersection = host[:roles] & mono_roles
        if roles_intersection.size != 3 && roles_intersection.any?
          host[:additional_ports] ? host[:additional_ports].push(8143) : host[:additional_ports] = [8143]
        end
      end
    end
  end
end
