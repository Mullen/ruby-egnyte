module Egnyte

  class Permission

    attr_accessor :data
    ### Representative Structure of @data
    # v1
    # {
    #   'users': {
    #     'jsmith': 'Full',
    #     'jdoe': 'Editor'
    #   },
    #   'groups': {
    #     'employees': 'Full',
    #     'partners': 'Viewer'
    #   }
    # }

    # v2
    # {
    #   "userPerms": {
    #     "jsmith": "Viewer",
    #     "ajones": "Editor"
    #   },
    #   "groupPerms": {
    #     "Project Team": "Full",
    #     "Contractors": "None"
    #   }
    # }

    @@valid_perm_levels = ["None", "Viewer", "Editor", "Full", "Owner"]

    def initialize(permissions_hash={})
      raise Egnyte::InvalidParameters unless (permissions_hash.empty? or permissions_hash['userPerms'] or permissions_hash['groupPerms'])
      @data = empty_permissions_hash
      merge!(permissions_hash)
    end

    def merge(new_perm_set)
      old_perm_set = @data.dup
      new_perm_set = new_perm_set.data if new_perm_set.class == Egnyte::Permission
      raise Egnyte::InvalidParameters unless new_perm_set.class == Hash
      new_perm_set.each do |type, perms_hash|
        old_perm_set[type] = perms_hash
      end
      old_perm_set
    end

    def merge!(new_perm_set)
      @data = merge(new_perm_set)
    end

    def empty_permissions_hash
      Egnyte::Permission.empty_permissions_hash
    end

    def self.empty_permissions_hash
      { 'userPerms' => {}, 'groupPerms' => {} }
    end

    def self.build_from_api_listing(json_listing)
      perm = empty_permissions_hash
      json_listing.each do |type, data|
        data.each do |item|
          perm[type][item["subject"]] = item["permission"]
        end
      end
      Egnyte::Permission.new(perm)
    end

    def self.folder_permissions(session, path, params=nil)
      path = Egnyte::Helper.normalize_path(path)
      path += Egnyte::Helper.params_to_filter_string(params) if params
      response = session.get("#{self.permission_path(session)}/#{path}")
      self.build_from_api_listing(response)
    end

    def self.inherited_permissions(session, path, params=nil)
      path = Egnyte::Helper.normalize_path(path)
      path = path.split('/')[0..-2].join('/')
      self.folder_permissions(session, path, params)
    end

    def self.explicit_permissions(session, path, params=nil)
      inherited = self.inherited_permissions(session, path, params).data
      permissions = self.folder_permissions(session, path, params).data
      explicit = self.empty_permissions_hash

      #filter out permissions that exist in the parent folder's permissions
      permissions.each do |type, perm|
        perm.each do |k,v|
          explicit[type][k] = v unless inherited[type][k] == v
        end
      end
      self.new(explicit)
    end

    def self.permission_path(session)
      "https://#{session.domain}.#{EGNYTE_DOMAIN}/#{session.api}/v2/perms"
    end

    def valid?
      return @data['userPerms'].class == Hash && @data['groupPerms'].class == Hash
    end

    def has_data?
      return @data['userPerms'].size > 0 || @data['groupPerms'].size > 0
    end

    def empty?
      return !has_data?
    end

    def to_hash
      @data
    end

    def to_json
      to_hash.to_json
    end

    def to_s
      to_json
    end

    def self.apply(session, permission_object, target_path)
      if permission_object.valid? and permission_object.has_data?
          session.post("#{self.permission_path(session)}/#{target_path}", permission_object.data.to_json, false)
        "Permissions set on #{target_path}: #{permission_object.to_hash}"
      end
    end

    def ==(other_perm_object)
      @data == other_perm_object.data
    end

    def diff(other_perm_object)
      only_originial = Egnyte::Permission.new
      common_perms   = Egnyte::Permission.new
      only_other     = Egnyte::Permission.new
      discrepancies  = {'original' => Egnyte::Permission.new, 'other' => Egnyte::Permission.new}

      # find whether permission is only in the self's set or is common between self and other
      @data.each do |level, perm_hash|
        perm_hash.each do |item, permission|
          if other_perm_object.data[level][item].nil?
            only_originial.data[level][item] = permission
          elsif other_perm_object.data[level][item] != permission
            discrepancies['original'].data[level][item] = permission
            discrepancies['other'].data[level][item] = other_perm_object.data[level][item]
          end
          common_perms.data[level][item]   = permission if other_perm_object.data[level][item] == permission
        end
      end

      # find whether permission is in the other_perm_object
      other_perm_object.data.each do |level, perm_hash|
        perm_hash.each do |item, permission|
            only_other.data[level][item] = permission if @data[level][item].nil? || @data[level][item] != permission
        end
      end

      [only_originial, common_perms, only_other, discrepancies]
    end

  end

end
