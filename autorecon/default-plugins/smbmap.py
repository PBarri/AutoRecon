from autorecon.plugins import ServiceScan

class SMBMap(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SMBMap"
		self.tags = ['default', 'safe', 'smb', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\-ds', '^netbios'])

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			if self.get_global('username') and (self.get_global('password') or self.get_global('hash')):
				auth_args = ' -u "' + self.get_global('username') + '"'
				if self.get_global('password'):
					auth_args += ' -p "' + self.get_global('password') + '"'
				elif self.get_global('hash'):
					auth_args += ' -p "' + self.get_global('hash') + '"'
				
				if self.get_global('domain'):
					auth_args += ' -d "' + self.get_global('domain') + '"'

				await service.execute('smbmap -H {address} -P {port}' + auth_args + ' 2>&1', outfile='smbmap-share-permissions.txt')
				await service.execute('smbmap -H {address} -P {port} -r' + auth_args + ' 2>&1', outfile='smbmap-list-contents.txt')
				await service.execute('smbmap -H {address} -P {port} -x "ipconfig /all"' + auth_args + ' 2>&1', outfile='smbmap-execute-command.txt')
			else:
				await service.execute('smbmap -H {address} -P {port} 2>&1', outfile='smbmap-share-permissions.txt')
				await service.execute('smbmap -u null -p "" -H {address} -P {port} 2>&1', outfile='smbmap-share-permissions.txt')
				await service.execute('smbmap -H {address} -P {port} -r 2>&1', outfile='smbmap-list-contents.txt')
				await service.execute('smbmap -u null -p "" -H {address} -P {port} -r 2>&1', outfile='smbmap-list-contents.txt')
				await service.execute('smbmap -H {address} -P {port} -x "ipconfig /all" 2>&1', outfile='smbmap-execute-command.txt')
				await service.execute('smbmap -u null -p "" -H {address} -P {port} -x "ipconfig /all" 2>&1', outfile='smbmap-execute-command.txt')

	def manual(self, service, plugin_was_run):
		if not self.get_global('username') or not (self.get_global('password') or self.get_global('hash')):
			service.add_manual_command('Try authenticated scan. Requires credentials', [
				'smbmap -H {address} -P {port} -u <username> -p <password>  2>&1 | tee {scandir}/smbmap-share-permissions.txt'
			])
