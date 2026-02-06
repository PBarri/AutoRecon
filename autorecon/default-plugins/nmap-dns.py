from autorecon.plugins import ServiceScan

class NmapDNS(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap DNS'
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA "{scandir}/{protocol}_{port}_dns_nmap" {address}')
