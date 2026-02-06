from autorecon.plugins import ServiceScan

class NmapCUPS(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap CUPS"
		self.tags = ['default', 'safe', 'cups']

	def configure(self):
		self.match_service_name('^ipp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(cups* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA "{scandir}/{protocol}_{port}_cups_nmap" {address}')
