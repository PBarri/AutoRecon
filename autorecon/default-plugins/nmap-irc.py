from autorecon.plugins import ServiceScan

class NmapIrc(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap IRC'
		self.tags = ['default', 'safe', 'irc']

	def configure(self):
		self.match_service_name('^irc')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -oA "{scandir}/{protocol}_{port}_irc_nmap" -p {port} {address}')
