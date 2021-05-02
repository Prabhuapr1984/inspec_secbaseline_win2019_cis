require 'yaml'

SIDS_NAMES = {
  'S-1-1-0' => 'Everyone',
  'S-1-5-11' => 'Authenticated Users',
  'S-1-5-19' => 'LOCAL SERVICE',
  'S-1-5-2' => 'NETWORK',
  'S-1-5-20' => 'NETWORK SERVICE',
  'S-1-5-6' => 'SERVICE',
  'S-1-5-32-555' => 'Remote Desktop Users',
  'S-1-5-32-544' => 'Administrators',
  'S-1-5-32-551' => 'Backup Operators',
  'S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420' => 'WdiServiceHost',
  'S-1-5-80-344959196-2060754871-2302487193-2804545603-1466107430' => 'SQLSERVERAGENT',
  'S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003' => 'MSSQLSERVER'
}

NAMES_SIDS = {
  'Guests' => 'S-1-5-32-546',
  'Administrators' => 'S-1-5-32-544',
  'Backup Operators' => 'S-1-5-32-551'
}

# Custom resource based on the InSpec resource DSL
class WinSIDs < Inspec.resource(1)
  name 'win_sids'

  supports platform: 'windows'

  desc "
    Windows SIDs
  "

  example "
    describe win_sids do
      its('version') { should eq('0.1') }
    end
  "

  # Load the configuration file on initialization
  def initialize()
    @params = {}
    @params['version'] = '0.1'
    @params['sids2names'] = SIDS_NAMES

    # Protect from invalid YAML content
    begin
    rescue StandardError => e
      raise Inspec::Exceptions::ResourceSkipped, "#{@file}: #{e.message}"
    end
  end

  def has_sid?(sid)
    return @params['sids2names'].key?(sid)
  end

  def to_name(sid)
    if ! has_sid?(sid)
      cmd = inspec.command("(New-Object System.Security.Principal.SecurityIdentifier('#{sid}')).Translate([System.Security.Principal.NTAccount]).value")
      @params['sids2names'][sid] = cmd.stdout.chomp.sub(/^BUILTIN\\/, '')
    end

    return @params['sids2names'][sid]
  end

  def sids2names(sids)
    sids.each do |entry|
      sids = sids - [entry] + [ to_name(entry) ] if (entry =~ /^S-/)
    end

    return sids
  end

  def get_sid(name)
    return NAMES_SIDS[name] if NAMES_SIDS.key?(name)
    return @params['sids2names'].key(name)
  end

  # Expose all parameters
  def method_missing(name)
    @params[name.to_s]
  end
end
