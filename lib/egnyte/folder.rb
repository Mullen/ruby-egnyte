module Egnyte

  class Client
    def folder(path='Shared')
      Folder::find(@session, path)
    end

    def create_folder(path)
      Folder::create(@session, path)
    end

    def delete_folder(path)
      Folder::delete(@session, path)
    end
  end

  class Folder < Item
    def create(path)
      path = Egnyte::Helper.normalize_path(path)
      new_folder_path = "#{self.path}/#{path}"
      Egnyte::Folder.create(@session, new_folder_path)
    end

    def self.create(session, path)
      path = Egnyte::Helper.normalize_path(path)
      session.post("#{Egnyte::Item.fs_path(session)}#{path}", JSON.dump({
        action: 'add_folder'
      }))

      Folder.new({
        'path' => path,
        'folders' => [],
        'is_folder' => true,
        'name' => path.split('/').pop
      }, session)
    end

    def patch(options)
      response = session.patch("#{Egnyte::Item.fs_path(session)}#{path}", JSON.dump(options))
      update_data(response)
    end

    def delete
      Egnyte::Folder.delete(@session, path)
    end

    def self.delete(session, path)
      session.delete("#{Egnyte::Item.fs_path(session)}/#{path}")
    end

    def upload(filename, content)
      resp = @session.multipart_post("#{fs_path('fs-content')}#{path}/#{filename}", filename, content, false)

      content.rewind # to calculate size, rewind content stream.

      File.new({
        'is_folder' => false,
        'entry_id' => resp['ETag'],
        'checksum' => resp['X-Sha512-Checksum'],
        'last_modified' => resp['Last-Modified'],
        'name' => filename,
        'size' => content.size
      }, @session)
    end

    def files
      create_objects(File, 'files')
    end

    def folders
      create_objects(Folder, 'folders')
    end

    def self.find(session, path)
      path = Egnyte::Helper.normalize_path(path)

      folder = Folder.new({
        'path' => path
      }, session)

      parsed_body = session.get("#{folder.fs_path}#{path}")

      raise FolderExpected unless parsed_body['is_folder']

      folder.update_data(parsed_body)
    end

    def permissions(params=nil)
      Egnyte::Permission.folder_permissions(@session, @data['path'])
    end

    def inherited_permissions(params=nil)
      Egnyte::Permission.inherited_permissions(@session, @data['path'])
    end

    def explicit_permissions(params=nil)
      Egnyte::Permission.explicit_permissions(@session, @data['path'])
    end

    def apply_permissions(permission_object)
      Egnyte::Permission.apply(@session, permission_object, @data['path'])
    end

    private

    def create_objects(klass, key)
      return [] unless @data[key]
      @data[key].map do |data|
        data = data.merge({
          'path' => "#{path}/#{data['name']}"
        })
        klass.new(data, @session)
      end
    end

  end
end
