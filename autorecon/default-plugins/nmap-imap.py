from autorecon.plugins import ServiceScan

class NmapIMAP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap IMAP"
		self.tags = ['default', 'safe', 'imap', 'email']

	def configure(self):
		self.match_service_name('^imap')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(imap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA "{scandir}/{protocol}_{port}_imap_nmap" {address}')
